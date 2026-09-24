pub mod app;
mod conntrack;
mod dashboard;
mod detail_block;
mod hardirq;
mod health;
mod module_frame;
mod netdev;
mod netfilter;
mod network_route;
mod presentation;
mod socket;
mod socket_detail;
mod sort_table;
mod summary;
mod tc;
mod theme;
mod view;

use std::ffi::CStr;
use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use app::{Action, App, DashboardMode, Effect};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::collect::SystemPaths;
use crate::monitor::conntrack_flow::ConntrackFlowSession;
use crate::monitor::network_route::NetworkRouteSession;
use crate::monitor::socket_table::SocketTableSession;
use crate::monitor::{InitialPage, MonitorPlan, MonitorSection, MonitorSession};

pub fn run(plan: MonitorPlan, paths: SystemPaths) -> anyhow::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        anyhow::bail!("interactive terminal required on stdin and stdout");
    }

    let signals = SignalGuard::install()?;
    let mut session = Some(MonitorSession::start(plan.clone(), paths.clone())?);
    let interface_name_alias = interface_name_alias(plan.interface_anchor());
    let mut app = App::new(plan.initial_section(), plan.interval().get())
        .with_interface_anchor(plan.interface_anchor().cloned())
        .with_interface_name_alias(interface_name_alias);
    if let Some(page) = plan.initial_page() {
        app.select_page(match page {
            InitialPage::Overview => app::Page::Overview,
            InitialPage::Interface => app::Page::Netdev,
            InitialPage::Qdisc => app::Page::Tc,
            InitialPage::Softirq => app::Page::Softirq,
            InitialPage::Hardirq => app::Page::Hardirq,
            InitialPage::Socket => app::Page::Socket,
            InitialPage::Transport => app::Page::Transport,
            InitialPage::Network => app::Page::Network,
            InitialPage::Conntrack => app::Page::Conntrack,
            InitialPage::Route => app::Page::Route,
            InitialPage::Providers => app::Page::Providers,
        });
    }
    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).context("initialize terminal backend")?;
    terminal.clear().context("clear terminal")?;

    let loop_result = run_loop(
        &mut terminal,
        &mut app,
        session.as_ref().expect("session exists"),
        signals.terminated(),
        &paths,
    );
    let shutdown_result = session
        .take()
        .expect("session exists until TUI shutdown")
        .shutdown();
    drop(terminal);
    drop(guard);
    let result = loop_result.and(shutdown_result);
    if result.is_ok() && signals.was_terminated() {
        anyhow::bail!("received SIGINT or SIGTERM");
    }
    result
}

fn interface_name_alias(anchor: Option<&crate::monitor::InterfaceViewAnchor>) -> Option<String> {
    let crate::monitor::InterfaceViewAnchor::Ifindex { ifindex } = anchor? else {
        return None;
    };
    let mut buffer = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: the buffer is writable for IFNAMSIZ bytes, as required by if_indextoname.
    let name = unsafe { libc::if_indextoname(ifindex.get(), buffer.as_mut_ptr()) };
    if name.is_null() {
        return None;
    }
    // SAFETY: if_indextoname returned a pointer into buffer and NUL-terminated it on success.
    let name = unsafe { CStr::from_ptr(name) }.to_str().ok()?;
    crate::collect::valid_interface_name(name).then(|| name.to_owned())
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    session: &MonitorSession,
    terminated: &AtomicBool,
    paths: &SystemPaths,
) -> anyhow::Result<()> {
    let mut sequence = 0;
    let mut socket_sequence = 0;
    let mut socket_session = None;
    let mut conntrack_sequence = 0;
    let mut conntrack_session = None;
    let mut network_route_sequence = 0;
    let mut network_route_session = None;
    let mut needs_redraw = true;
    let mut input_redraw = true;
    let mut last_draw = Instant::now();
    loop {
        if terminated.load(Ordering::SeqCst) {
            return Ok(());
        }
        session.set_focus(app.collection_focus());
        reconcile_network_route_session(
            app,
            &mut network_route_session,
            &mut network_route_sequence,
        )?;
        reconcile_socket_session(app, &mut socket_session, &mut socket_sequence, paths)?;
        reconcile_conntrack_session(app, &mut conntrack_session, &mut conntrack_sequence, paths)?;
        if let Some(snapshot) = session.wait_after(sequence, Duration::from_millis(25))? {
            sequence = snapshot.sequence();
            app.apply_snapshot(snapshot);
            needs_redraw |= !app.paused();
        }
        if let Some(route_session) = &network_route_session {
            if let Some(snapshot) =
                route_session.wait_after(network_route_sequence, Duration::ZERO)?
            {
                network_route_sequence = snapshot.sequence();
                app.apply_network_route_snapshot(snapshot);
                needs_redraw |= !app.paused() && app.is_network_route();
            }
        }
        if let Some(flow_session) = &conntrack_session {
            if let Some(snapshot) = flow_session.wait_after(conntrack_sequence, Duration::ZERO)? {
                conntrack_sequence = snapshot.sequence();
                app.apply_conntrack_snapshot(snapshot);
                needs_redraw |= !app.paused() && app.is_conntrack_flows();
            }
        }
        if let Some(table_session) = &socket_session {
            if let Some(snapshot) = table_session.wait_after(socket_sequence, Duration::ZERO)? {
                socket_sequence = snapshot.sequence();
                app.apply_socket_snapshot(snapshot);
                needs_redraw |= !app.paused() && app.is_socket_session_active();
            }
        }
        if needs_redraw && (input_redraw || last_draw.elapsed() >= Duration::from_millis(100)) {
            terminal
                .draw(|frame| {
                    app.set_viewport_size(frame.area().width, view::body_rows(frame.area(), app));
                    view::render(frame, app);
                })
                .context("render terminal UI")?;
            needs_redraw = false;
            input_redraw = false;
            last_draw = Instant::now();
        }

        if !event::poll(Duration::from_millis(25)).context("poll terminal input")? {
            continue;
        }
        match event::read().context("read terminal input")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if let Some(action) = action_for_key(app, key) {
                    if app.update(action) == Effect::Exit {
                        return Ok(());
                    }
                    needs_redraw = true;
                    input_redraw = true;
                }
            }
            Event::Resize(_, _) => {
                needs_redraw = true;
                input_redraw = true;
            }
            Event::Mouse(mouse) => {
                let action = match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => Some(Action::Click {
                        column: mouse.column,
                        row: mouse.row,
                    }),
                    MouseEventKind::ScrollUp => Some(Action::ScrollUp),
                    MouseEventKind::ScrollDown => Some(Action::ScrollDown),
                    _ => None,
                };
                if let Some(action) = action {
                    app.update(action);
                    needs_redraw = true;
                    input_redraw = true;
                }
            }
            Event::FocusGained | Event::FocusLost | Event::Key(_) | Event::Paste(_) => {}
        }
    }
}

fn reconcile_network_route_session(
    app: &mut App,
    session: &mut Option<NetworkRouteSession>,
    sequence: &mut u64,
) -> anyhow::Result<()> {
    if app.is_network_route() {
        if session.is_none() {
            *sequence = 0;
            app.clear_network_route_snapshots();
            let started = NetworkRouteSession::start(app.interval())?;
            started.set_foreground(true);
            *session = Some(started);
        }
    } else if let Some(stopped) = session.take() {
        stopped.shutdown()?;
        *sequence = 0;
        app.clear_network_route_snapshots();
    }
    Ok(())
}

fn reconcile_conntrack_session(
    app: &App,
    session: &mut Option<ConntrackFlowSession>,
    sequence: &mut u64,
    paths: &SystemPaths,
) -> anyhow::Result<()> {
    if app.is_conntrack_flows() {
        if session.is_none() {
            *sequence = 0;
            *session = Some(ConntrackFlowSession::start(app.interval(), paths.clone())?);
        }
    } else if let Some(session) = session.take() {
        *sequence = 0;
        session.shutdown()?;
    }
    Ok(())
}

fn reconcile_socket_session(
    app: &App,
    session: &mut Option<SocketTableSession>,
    sequence: &mut u64,
    paths: &SystemPaths,
) -> anyhow::Result<()> {
    if app.is_socket_session_active() {
        if session.is_none() {
            *sequence = 0;
            *session = Some(SocketTableSession::start(app.interval(), paths.clone())?);
        }
    } else if let Some(session) = session.take() {
        *sequence = 0;
        session.shutdown()?;
    }
    Ok(())
}

struct SignalGuard {
    terminated: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
}

impl SignalGuard {
    fn install() -> anyhow::Result<Self> {
        let terminated = Arc::new(AtomicBool::new(false));
        let mut registrations = Vec::with_capacity(2);
        for signal in [SIGINT, SIGTERM] {
            match signal_hook::flag::register(signal, Arc::clone(&terminated)) {
                Ok(registration) => registrations.push(registration),
                Err(error) => {
                    for registration in registrations.drain(..) {
                        signal_hook::low_level::unregister(registration);
                    }
                    return Err(error).context("install terminal shutdown signal handler");
                }
            }
        }
        Ok(Self {
            terminated,
            registrations,
        })
    }

    fn terminated(&self) -> &AtomicBool {
        &self.terminated
    }

    fn was_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn action_for_key(app: &App, key: KeyEvent) -> Option<Action> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Some(Action::Quit);
    }
    if key.code == KeyCode::Char('u')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && (app.is_socket_table() || app.is_conntrack_flows())
        && (!app.text_input_active()
            || app.socket_filter_input().is_some()
            || app.flow_filter_input().is_some())
    {
        return Some(Action::ClearConnectionFilter);
    }
    if app.text_input_active() {
        return match key.code {
            KeyCode::Esc => Some(Action::CancelCommand),
            KeyCode::Enter => Some(Action::SubmitCommand),
            KeyCode::Backspace => Some(Action::Backspace),
            KeyCode::Char(character) => Some(Action::Insert(character)),
            _ => None,
        };
    }
    match key.code {
        KeyCode::Tab => Some(Action::NextPage),
        KeyCode::BackTab => Some(Action::PreviousPage),
        KeyCode::Char('s') => Some(Action::CycleSort),
        KeyCode::Char('r') => Some(Action::ReverseSort),
        KeyCode::Char('v') if app.is_tc_view() => Some(Action::ToggleTcMetrics),
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char(':') => Some(Action::EnterCommand),
        KeyCode::Char('/') if app.is_conntrack_flows() => Some(Action::EnterFlowFilter),
        KeyCode::Char('/') if app.is_socket_table() => Some(Action::EnterSocketFilter),
        KeyCode::Char('d') if app.is_conntrack_flows() => Some(Action::OpenConntrackDiagnostics),
        KeyCode::Char('p' | ' ') => Some(Action::TogglePause),
        KeyCode::Char('t') if !app.is_socket_detail() => Some(Action::ToggleTimeView),
        KeyCode::Char('a')
            if app.is_overview_detail()
                || app.is_softirq_view()
                || app.is_socket_detail()
                || app.is_network_route_metrics()
                || app.is_netfilter_conntrack() =>
        {
            Some(Action::ToggleDetailMetrics)
        }
        KeyCode::Up | KeyCode::Char('k')
            if app.section() == MonitorSection::Overview
                && app.dashboard_mode() == DashboardMode::Summary =>
        {
            Some(Action::SelectPreviousOverviewItem)
        }
        KeyCode::Down | KeyCode::Char('j')
            if app.section() == MonitorSection::Overview
                && app.dashboard_mode() == DashboardMode::Summary =>
        {
            Some(Action::SelectNextOverviewItem)
        }
        KeyCode::Up | KeyCode::Char('k') if app.is_interface_detail() => {
            Some(Action::SelectPreviousInterfaceLayer)
        }
        KeyCode::Down | KeyCode::Char('j') if app.is_interface_detail() => {
            Some(Action::SelectNextInterfaceLayer)
        }
        KeyCode::Up | KeyCode::Char('k') => Some(Action::ScrollUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::ScrollDown),
        KeyCode::Enter if app.is_tc_view() => Some(Action::OpenTcItem),
        KeyCode::Enter if app.is_conntrack_list() => Some(Action::OpenConntrackDetail),
        KeyCode::Enter if app.is_netdev_table() => Some(Action::OpenSelectedOverviewItem),
        KeyCode::Enter
            if app.section() == MonitorSection::Overview
                && app.dashboard_mode() == DashboardMode::Summary =>
        {
            Some(Action::OpenSelectedOverviewItem)
        }
        KeyCode::Enter if app.can_open_interface_layer_detail() => {
            Some(Action::OpenSelectedInterfaceLayer)
        }
        KeyCode::Enter if app.can_open_socket_table() => Some(Action::OpenSocketTable),
        KeyCode::Enter if app.can_open_socket_detail() => Some(Action::OpenSocketDetail),
        KeyCode::Enter if app.can_open_conntrack_flows() => Some(Action::OpenConntrackFlows),
        KeyCode::Enter if app.is_netfilter_view() => Some(Action::OpenNetfilterItem),
        KeyCode::Enter if app.is_network_route() => Some(Action::OpenNetworkRouteItem),
        KeyCode::Esc if app.is_detail() || app.is_tc_view() => Some(Action::Back),
        KeyCode::PageUp => Some(Action::PageUp),
        KeyCode::PageDown => Some(Action::PageDown),
        KeyCode::Home => Some(Action::ScrollTop),
        KeyCode::Left | KeyCode::Right | KeyCode::Char('0'..='9') => None,
        _ => None,
    }
}

struct TerminalGuard {
    raw: bool,
    alternate_screen: bool,
    cursor_hidden: bool,
}

impl TerminalGuard {
    fn enter() -> anyhow::Result<Self> {
        let mut guard = Self {
            raw: false,
            alternate_screen: false,
            cursor_hidden: false,
        };
        enable_raw_mode().context("enable terminal raw mode")?;
        guard.raw = true;
        execute!(io::stdout(), EnterAlternateScreen).context("enter alternate terminal screen")?;
        guard.alternate_screen = true;
        execute!(io::stdout(), Hide).context("hide terminal cursor")?;
        guard.cursor_hidden = true;
        execute!(io::stdout(), EnableMouseCapture).context("enable terminal mouse")?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture);
        if self.cursor_hidden {
            let _ = execute!(io::stdout(), Show);
        }
        if self.alternate_screen {
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
        }
        if self.raw {
            let _ = disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_worker_exists_only_on_its_page_and_accepts_restarted_sequences() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(60));
        let mut session = None;
        let mut sequence = 0;
        reconcile_network_route_session(&mut app, &mut session, &mut sequence).unwrap();
        assert!(session.is_none());
        for _ in 0..2 {
            app.update(Action::SelectPage(app::Page::Route));
            reconcile_network_route_session(&mut app, &mut session, &mut sequence).unwrap();
            let snapshot = session
                .as_ref()
                .unwrap()
                .wait_after(0, Duration::from_secs(3))
                .unwrap()
                .unwrap();
            sequence = snapshot.sequence();
            app.apply_network_route_snapshot(snapshot);
            assert_eq!(app.network_route_snapshot().unwrap().sequence(), sequence);
            let retained = session.as_ref().unwrap() as *const _;
            app.update(Action::OpenNetworkRouteItem);
            reconcile_network_route_session(&mut app, &mut session, &mut sequence).unwrap();
            assert_eq!(session.as_ref().unwrap() as *const _, retained);
            app.update(Action::SelectPage(app::Page::Socket));
            reconcile_network_route_session(&mut app, &mut session, &mut sequence).unwrap();
            assert!(session.is_none());
            assert_eq!(sequence, 0);
            assert!(app.network_route_snapshot().is_none());
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn interface_detail_app() -> App {
        let elapsed = Duration::from_secs(1);
        let labels = crate::monitor::MetricLabels::new([
            (crate::monitor::MetricLabel::Interface, "eth0".to_owned()),
            (crate::monitor::MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let reading = crate::monitor::SampleReading::observed(
            crate::monitor::MetricId::new("linux.nic.interface_kind").unwrap(),
            labels,
            crate::monitor::MetricReading::State(
                crate::monitor::StateValue::new("physical").unwrap(),
            ),
        );
        let sample = crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.sysfs.net.nic").unwrap(),
            elapsed,
            Duration::from_millis(1),
            crate::monitor::ProviderHealth::Fresh,
            vec![reading],
        )
        .unwrap();
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        let snapshot = engine.ingest(elapsed, vec![sample], None).unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed);
        app.apply_snapshot(snapshot);
        for _ in 0..app::workspace::LAYERS.len() {
            app.update(Action::SelectNextOverviewItem);
        }
        app.update(Action::OpenSelectedOverviewItem);
        app
    }

    fn conntrack_detail_app() -> App {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        while app.selected_layer()
            != Some(crate::monitor::dashboard::BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::NetfilterConntrack,
            ))
        {
            app.update(Action::SelectNextOverviewItem);
        }
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.is_conntrack_flows());
        app
    }

    fn socket_detail_app() -> App {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.can_open_socket_table());
        app
    }

    fn network_route_detail_app() -> App {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::SelectPage(app::Page::Route));
        assert!(app.is_network_route());
        app
    }

    #[test]
    fn overview_keys_select_items_and_open_details() {
        let app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        assert_eq!(
            action_for_key(&app, key(KeyCode::Up)),
            Some(Action::SelectPreviousOverviewItem)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Down)),
            Some(Action::SelectNextOverviewItem)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenSelectedOverviewItem)
        );
    }

    #[test]
    fn tabs_switch_pages_but_horizontal_and_number_keys_do_not() {
        let app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        for code in [
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Char('0'),
            KeyCode::Char('6'),
            KeyCode::Char('9'),
            KeyCode::Char('h'),
        ] {
            assert_eq!(action_for_key(&app, key(code)), None);
        }
        assert_eq!(
            action_for_key(&app, key(KeyCode::Tab)),
            Some(Action::NextPage)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::BackTab)),
            Some(Action::PreviousPage)
        );
    }

    #[test]
    fn q_is_text_while_command_mode_is_active() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::EnterCommand);
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('q'))),
            Some(Action::Insert('q'))
        );
    }

    #[test]
    fn control_c_quits_even_while_command_mode_is_active() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::EnterCommand);
        let control_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

        assert_eq!(action_for_key(&app, control_c), Some(Action::Quit));
    }

    #[test]
    fn detail_and_command_mode_keys_have_distinct_enter_and_escape_actions() {
        let mut app = interface_detail_app();
        assert_eq!(
            action_for_key(&app, key(KeyCode::Down)),
            Some(Action::SelectNextInterfaceLayer)
        );
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenSelectedInterfaceLayer)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('a'))),
            Some(Action::ToggleDetailMetrics)
        );

        app.update(Action::OpenSelectedInterfaceLayer);
        assert!(app.is_interface_layer_detail());
        assert_eq!(
            action_for_key(&app, key(KeyCode::Down)),
            Some(Action::ScrollDown)
        );
        assert_eq!(action_for_key(&app, key(KeyCode::Enter)), None);

        app.update(Action::EnterCommand);
        assert_eq!(
            action_for_key(&app, key(KeyCode::Esc)),
            Some(Action::CancelCommand)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::SubmitCommand)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('a'))),
            Some(Action::Insert('a'))
        );
    }

    #[test]
    fn conntrack_list_enter_opens_detail_and_slash_starts_filtering() {
        let mut app = conntrack_detail_app();
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenConntrackDetail)
        );

        app.update(Action::OpenConntrackFlows);
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('/'))),
            Some(Action::EnterFlowFilter)
        );
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('s'))),
            Some(Action::CycleSort)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('r'))),
            Some(Action::ReverseSort)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('d'))),
            Some(Action::OpenConntrackDiagnostics)
        );
    }

    #[test]
    fn socket_detail_enter_opens_the_socket_table() {
        let mut app = socket_detail_app();
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenSocketTable)
        );

        app.update(Action::OpenSocketTable);
        assert!(app.is_socket_table());
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        assert_eq!(action_for_key(&app, key(KeyCode::Enter)), None);
    }

    #[test]
    fn selected_socket_uses_enter_and_three_layer_escape_navigation() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenSocketDetail)
        );

        app.update(Action::OpenSocketDetail);
        assert!(app.is_socket_detail());
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        assert_eq!(action_for_key(&app, key(KeyCode::Char('t'))), None);
        app.update(Action::Back);
        assert!(app.is_socket_table());
        app.update(Action::Back);
        assert_eq!(app.section(), MonitorSection::Socket);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        app.update(Action::Back);
        assert_eq!(app.section(), MonitorSection::Overview);
    }

    #[test]
    fn network_route_uses_enter_and_layered_escape_navigation() {
        let mut app = network_route_detail_app();
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenNetworkRouteItem)
        );

        app.update(Action::OpenNetworkRouteItem);
        assert!(app.is_network_route_metrics());
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        app.update(Action::Back);
        assert!(app.is_network_route());
        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(app.section(), MonitorSection::Overview);
    }

    #[test]
    fn route_lookup_input_uses_normal_text_input_keys() {
        let mut app = network_route_detail_app();
        for _ in 0..4 {
            app.update(Action::ScrollDown);
        }
        app.update(Action::OpenNetworkRouteItem);
        assert!(app.text_input_active());
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('q'))),
            Some(Action::Insert('q'))
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::SubmitCommand)
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Esc)),
            Some(Action::CancelCommand)
        );
        app.update(Action::CancelCommand);
        assert!(app.is_network_route());
        assert!(!app.text_input_active());
    }

    #[test]
    fn direct_socket_section_uses_enter_then_two_escape_steps() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenSocketTable)
        );

        app.update(Action::OpenSocketTable);
        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        app.update(Action::Back);
        assert_eq!(app.section(), MonitorSection::Socket);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);

        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
        app.update(Action::Back);
        assert_eq!(app.section(), MonitorSection::Overview);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
    }

    #[test]
    fn direct_netfilter_section_enters_conntrack_before_opening_flows() {
        let mut app = App::new(MonitorSection::Netfilter, Duration::from_secs(1));
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenNetfilterItem)
        );
        app.update(Action::OpenNetfilterItem);
        assert_eq!(
            action_for_key(&app, key(KeyCode::Enter)),
            Some(Action::OpenConntrackFlows)
        );
    }

    #[test]
    fn conntrack_worker_exists_only_while_the_flow_page_is_open() {
        let root = tempfile::TempDir::new().unwrap();
        let paths = SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        };
        let mut app = App::new(MonitorSection::Netfilter, Duration::from_secs(1));
        let mut session = None;
        let mut sequence = 0;

        reconcile_conntrack_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_none());

        app.update(Action::OpenNetfilterItem);
        app.update(Action::OpenConntrackFlows);
        reconcile_conntrack_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_some());

        app.apply_conntrack_snapshot(conntrack::tests::fixture_snapshots().1);
        sequence = 17;
        app.update(Action::OpenConntrackDetail);
        assert!(app.conntrack_view().is_detail());
        for action in [
            Action::TogglePause,
            Action::TogglePause,
            Action::OpenConntrackDiagnostics,
            Action::Back,
        ] {
            app.update(action);
            reconcile_conntrack_session(&app, &mut session, &mut sequence, &paths).unwrap();
            assert!(session.is_some());
            assert_eq!(
                sequence, 17,
                "detail navigation must not restart collection"
            );
            assert_eq!(
                app.collection_focus(),
                crate::monitor::focus::CollectionFocus::ConntrackFlows
            );
        }
        assert!(app.is_conntrack_list());

        app.update(Action::Back);
        reconcile_conntrack_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_none());
        assert_eq!(sequence, 0);
    }

    #[test]
    fn socket_worker_spans_table_and_detail_but_stops_after_socket_pages() {
        let root = tempfile::TempDir::new().unwrap();
        let paths = SystemPaths {
            proc_root: root.path().join("proc"),
            sys_root: root.path().join("sys"),
        };
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        let mut session = None;
        let mut sequence = 0;

        reconcile_socket_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_none());

        app.update(Action::OpenSocketTable);
        reconcile_socket_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_some());

        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::OpenSocketDetail);
        reconcile_socket_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_some(), "detail must keep the table worker alive");

        app.update(Action::Back);
        reconcile_socket_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(
            session.is_some(),
            "returning to the table keeps the worker alive"
        );

        app.update(Action::Back);
        reconcile_socket_session(&app, &mut session, &mut sequence, &paths).unwrap();
        assert!(session.is_none());
        assert_eq!(sequence, 0);
    }

    #[test]
    fn control_u_clears_table_filters_even_while_editing() {
        let clear = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
        for page in [app::Page::Socket, app::Page::Conntrack] {
            let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
            assert_eq!(action_for_key(&app, clear), None);
            app.update(Action::SelectPage(page));
            assert_eq!(
                action_for_key(&app, clear),
                Some(Action::ClearConnectionFilter)
            );
            app.update(if page == app::Page::Socket {
                Action::EnterSocketFilter
            } else {
                Action::EnterFlowFilter
            });
            assert_eq!(
                action_for_key(&app, clear),
                Some(Action::ClearConnectionFilter)
            );
            app.update(Action::CancelCommand);
            app.update(Action::EnterCommand);
            assert_ne!(
                action_for_key(&app, clear),
                Some(Action::ClearConnectionFilter)
            );
        }
    }

    #[test]
    fn q_and_numbers_are_text_while_flow_filter_is_active() {
        let mut app = conntrack_detail_app();
        app.update(Action::OpenConntrackFlows);
        app.update(Action::EnterFlowFilter);

        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('q'))),
            Some(Action::Insert('q'))
        );
        assert_eq!(
            action_for_key(&app, key(KeyCode::Char('4'))),
            Some(Action::Insert('4'))
        );
    }

    #[test]
    fn metric_visibility_shortcut_also_works_on_direct_softirq_page() {
        let overview = App::new(MonitorSection::Overview, Duration::from_secs(1));
        let direct_section = App::new(MonitorSection::Softirq, Duration::from_secs(1));

        assert_eq!(action_for_key(&overview, key(KeyCode::Char('a'))), None);
        assert_eq!(
            action_for_key(&direct_section, key(KeyCode::Char('a'))),
            Some(Action::ToggleDetailMetrics)
        );
    }

    #[test]
    fn escape_returns_from_a_direct_section_to_overview() {
        let app = App::new(MonitorSection::Softirq, Duration::from_secs(1));

        assert_eq!(action_for_key(&app, key(KeyCode::Esc)), Some(Action::Back));
    }
}
