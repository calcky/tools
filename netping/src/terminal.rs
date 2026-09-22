use std::{
    io::{self, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Once,
    },
    time::Duration,
};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    style::{Attribute, ResetColor, SetAttribute},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, buffer::Buffer, style::Color};

use crate::ui::{self, State, View};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Up,
    Down,
    Pause,
    Reset,
    Quit,
}

pub fn validate() -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "terminal UI requires a TTY on stdin and stdout",
        ));
    }
    if std::env::var_os("TERM").is_some_and(|term| term == "dumb") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "terminal UI requires TERM other than dumb",
        ));
    }
    Ok(())
}

static RESTORE_PENDING: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK: Once = Once::new();

fn restore() {
    if !RESTORE_PENDING.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = disable_raw_mode();
    let mut out = io::stdout();
    let _ = execute!(out, ResetColor, SetAttribute(Attribute::Reset));
    let _ = execute!(out, Show);
    let _ = execute!(out, LeaveAlternateScreen);
    let _ = out.flush();
}

pub struct Terminal {
    screen: Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
    entered: bool,
    monochrome: bool,
}

impl Terminal {
    pub fn enter() -> io::Result<Self> {
        validate()?;
        let mut result = Self {
            screen: None,
            entered: false,
            monochrome: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
        };
        PANIC_HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore();
                previous(info);
            }));
        });
        enable_raw_mode()?;
        result.entered = true;
        RESTORE_PENDING.store(true, Ordering::SeqCst);
        // Crossterm's NO_COLOR handling can cancel bold; reset cell colors instead.
        crossterm::style::force_color_output(true);
        // The guard and panic hook cover failures during alternate-screen setup.
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        let mut screen = ratatui::Terminal::new(CrosstermBackend::new(io::stdout()))?;
        screen.clear()?;
        result.screen = Some(screen);
        Ok(result)
    }

    pub fn key(&mut self) -> io::Result<Option<Action>> {
        // Bound draining so resize/repeat storms cannot starve the probe reactor.
        for _ in 0..64 {
            if !event::poll(Duration::ZERO)? {
                break;
            }
            if let Event::Key(key) = event::read()? {
                if let Some(action) = action(key) {
                    return Ok(Some(action));
                }
            }
            // Ratatui checks the actual size on draw; stale resize events are ignored.
        }
        Ok(None)
    }

    pub fn draw(&mut self, view: &View, state: &mut State) -> io::Result<()> {
        if let Some(screen) = self.screen.as_mut() {
            screen.draw(|f| {
                ui::draw(f, view, state);
                if self.monochrome {
                    reset_colors(f.buffer_mut());
                }
            })?;
        }
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.entered {
            restore();
        }
    }
}

fn action(key: KeyEvent) -> Option<Action> {
    if key.kind == KeyEventKind::Release {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return Some(Action::Quit);
    }
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
    {
        return None;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => Some(Action::Up),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::Down),
        KeyCode::Char(' ') if key.kind == KeyEventKind::Press => Some(Action::Pause),
        KeyCode::Char('r') if key.kind == KeyEventKind::Press => Some(Action::Reset),
        KeyCode::Char('q') => Some(Action::Quit),
        _ => None,
    }
}

fn reset_colors(buffer: &mut Buffer) {
    for cell in &mut buffer.content {
        cell.set_fg(Color::Reset).set_bg(Color::Reset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        backend::TestBackend,
        style::{Modifier, Style},
        widgets::Paragraph,
    };

    #[test]
    fn keys_cover_navigation_controls_and_ignore_releases() {
        for (code, expected) in [
            (KeyCode::Up, Action::Up),
            (KeyCode::Char('k'), Action::Up),
            (KeyCode::Down, Action::Down),
            (KeyCode::Char('j'), Action::Down),
            (KeyCode::Char(' '), Action::Pause),
            (KeyCode::Char('r'), Action::Reset),
            (KeyCode::Char('q'), Action::Quit),
        ] {
            assert_eq!(
                action(KeyEvent::new(code, KeyModifiers::NONE)),
                Some(expected)
            );
            assert_eq!(
                action(KeyEvent::new_with_kind(
                    code,
                    KeyModifiers::NONE,
                    KeyEventKind::Release
                )),
                None
            );
        }
        assert_eq!(
            action(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Quit)
        );
        assert_eq!(
            action(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::ALT)),
            None
        );
        assert_eq!(
            action(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            None
        );
        assert_eq!(
            action(KeyEvent::new_with_kind(
                KeyCode::Char(' '),
                KeyModifiers::NONE,
                KeyEventKind::Repeat
            )),
            None
        );
        assert_eq!(
            action(KeyEvent::new_with_kind(
                KeyCode::Down,
                KeyModifiers::NONE,
                KeyEventKind::Repeat
            )),
            Some(Action::Down)
        );
    }

    #[test]
    fn monochrome_clears_colors_without_removing_bold_or_error_words() {
        let mut terminal = ratatui::Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal
            .draw(|f| {
                f.render_widget(
                    Paragraph::new("ERROR: connection refused").style(
                        Style::default()
                            .fg(Color::Red)
                            .bg(Color::Blue)
                            .add_modifier(Modifier::BOLD),
                    ),
                    f.area(),
                );
                reset_colors(f.buffer_mut());
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(0, 0)].symbol(), "E");
        assert!(buffer[(0, 0)].modifier.contains(Modifier::BOLD));
        assert!(buffer
            .content
            .iter()
            .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset));
    }
}
