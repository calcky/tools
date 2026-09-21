use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, widgets::Paragraph};

pub static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn signals() {
    // The handler only sets an atomic flag; cleanup happens on the main thread.
    unsafe {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::signal(sig, stop as *const () as libc::sighandler_t);
        }
    }
}

fn restore() {
    let _ = disable_raw_mode();
    let mut out = io::stdout();
    let _ = execute!(out, DisableMouseCapture, Show, LeaveAlternateScreen);
    let _ = out.flush();
}

pub struct Terminal {
    screen: Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
    entered: bool,
    monochrome: bool,
}

impl Terminal {
    pub fn enter(top: bool) -> io::Result<Self> {
        let mut result = Self {
            screen: None,
            entered: false,
            monochrome: std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
        };
        if top
            && io::stdin().is_terminal()
            && io::stdout().is_terminal()
            && std::env::var("TERM").as_deref() != Ok("dumb")
        {
            enable_raw_mode()?;
            result.entered = true;
            // Apply NO_COLOR to cells ourselves: Crossterm 0.28 can otherwise
            // emit empty SGR parameters, which also cancel bold text.
            crossterm::style::force_color_output(true);
            // The guard restores raw mode even if any subsequent setup step fails.
            execute!(io::stdout(), EnterAlternateScreen, Hide, EnableMouseCapture)?;
            let mut screen = ratatui::Terminal::new(CrosstermBackend::new(io::stdout()))?;
            screen.clear()?;
            result.screen = Some(screen);
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore();
                previous(info);
            }));
        }
        Ok(result)
    }

    pub fn active(&self) -> bool {
        self.screen.is_some()
    }

    pub fn key(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        if !self.active() || !event::poll(timeout)? {
            return Ok(None);
        }
        Ok(match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    Some(b'q')
                } else {
                    match key.code {
                        KeyCode::Char(c) if c.is_ascii() => Some(c as u8),
                        KeyCode::Up => Some(b'k'),
                        KeyCode::Down => Some(b'j'),
                        KeyCode::PageUp => Some(b'p'),
                        KeyCode::PageDown => Some(b' '),
                        KeyCode::Home => Some(b'g'),
                        KeyCode::End => Some(b'G'),
                        KeyCode::Tab => Some(b'\t'),
                        _ => None,
                    }
                }
            }
            Event::Mouse(mouse) => match mouse.kind {
                MouseEventKind::ScrollUp => Some(b'k'),
                MouseEventKind::ScrollDown => Some(b'j'),
                _ => None,
            },
            _ => None,
        })
    }

    pub fn sampling(&mut self) -> io::Result<()> {
        if let Some(screen) = self.screen.as_mut() {
            screen.draw(|f| {
                f.render_widget(Paragraph::new("irqtop | sampling... (q to quit)"), f.area())
            })?;
        }
        Ok(())
    }

    pub fn draw(&mut self, report: &crate::Frame, state: &mut crate::ui::State) -> io::Result<()> {
        if let Some(screen) = self.screen.as_mut() {
            screen.draw(|f| {
                crate::ui::draw(f, report, state);
                if self.monochrome {
                    for cell in &mut f.buffer_mut().content {
                        cell.set_fg(ratatui::style::Color::Reset)
                            .set_bg(ratatui::style::Color::Reset);
                    }
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

pub fn size() -> (usize, usize) {
    // Query stdout directly: Crossterm's non-TTY fallback spawns tput processes.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_row > 0
        && size.ws_col > 0
    {
        (usize::from(size.ws_row), usize::from(size.ws_col))
    } else {
        (24, 80)
    }
}

pub fn time() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut local: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut local).is_null() {
            return "--:--:--".into();
        }
        format!(
            "{:02}:{:02}:{:02}",
            local.tm_hour, local.tm_min, local.tm_sec
        )
    }
}
