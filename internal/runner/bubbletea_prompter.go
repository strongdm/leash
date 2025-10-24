package runner

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/strongdm/leash/internal/configstore"

	_ "embed"
)

//go:embed assets/logo.ans
var rawLogoANSI string

const (
	wizardCardWidth = 64
	// The card allocates 2 spaces of horizontal padding on each side within the
	// fixed-width container, so 60 columns remain for inner content.
	wizardInnerWidth = wizardCardWidth - 4
)

type bubbleTeaPrompter struct {
	in       io.Reader
	out      io.Writer
	project  string
	theme    wizardTheme
	version  string
	fallback configstore.Prompter

	lastResult *wizardResult
	logo       string
}

func newBubbleTeaPrompter(in io.Reader, out io.Writer, project string) *bubbleTeaPrompter {
	theme := newWizardTheme(supportsColor(out))
	return &bubbleTeaPrompter{
		in:         in,
		out:        out,
		project:    project,
		theme:      theme,
		version:    versionTag(),
		fallback:   newTerminalPrompter(in, out),
		lastResult: nil,
		logo:       prepareLogo(rawLogoANSI, theme.color),
	}
}

func (p *bubbleTeaPrompter) ConfirmMount(ctx context.Context, cmd, hostDir string) (bool, error) {
	model := newWizardModel(cmd, hostDir, p.project, p.version, p.theme, p.logo)
	prog := tea.NewProgram(model, tea.WithInput(p.in), tea.WithOutput(p.out), tea.WithContext(ctx))

	final, err := prog.Run()
	if err != nil {
		return p.fallback.ConfirmMount(ctx, cmd, hostDir)
	}
	m, ok := final.(*wizardModel)
	if !ok || m.err != nil {
		return p.fallback.ConfirmMount(ctx, cmd, hostDir)
	}

	p.lastResult = &wizardResult{mount: m.result.mount, scope: m.result.scope}
	return m.result.mount, nil
}

func (p *bubbleTeaPrompter) ChooseScope(ctx context.Context, cmd, cwd string) (configstore.ScopeChoice, error) {
	if p.lastResult != nil {
		scope := p.lastResult.scope
		p.lastResult = nil
		return scope, nil
	}
	return p.fallback.ChooseScope(ctx, cmd, cwd)
}

type wizardResult struct {
	mount bool
	scope configstore.ScopeChoice
}

type wizardTheme struct {
	color          bool
	accentColor    lipgloss.Color
	title          lipgloss.Style
	subtitle       lipgloss.Style
	label          lipgloss.Style
	value          lipgloss.Style
	option         lipgloss.Style
	optionActive   lipgloss.Style
	description    lipgloss.Style
	help           lipgloss.Style
	key            lipgloss.Style
	prefixActive   string
	prefixInactive string
}

func newWizardTheme(color bool) wizardTheme {
	if !color {
		return wizardTheme{
			color:          false,
			accentColor:    "",
			title:          lipgloss.NewStyle().Bold(true),
			subtitle:       lipgloss.NewStyle().Bold(true),
			label:          lipgloss.NewStyle().Faint(true),
			value:          lipgloss.NewStyle(),
			option:         lipgloss.NewStyle().PaddingLeft(2),
			optionActive:   lipgloss.NewStyle().PaddingLeft(2).Bold(true),
			description:    lipgloss.NewStyle().Faint(true).PaddingLeft(4),
			help:           lipgloss.NewStyle().Faint(true),
			key:            lipgloss.NewStyle().Bold(true),
			prefixActive:   ">",
			prefixInactive: " ",
		}
	}

	accent := lipgloss.Color("#58d4ff")
	muted := lipgloss.Color("#9fb3c8")

	return wizardTheme{
		color:        true,
		accentColor:  accent,
		title:        lipgloss.NewStyle().Foreground(accent).Bold(true),
		subtitle:     lipgloss.NewStyle().Foreground(accent).Faint(true),
		label:        lipgloss.NewStyle().Faint(true),
		value:        lipgloss.NewStyle().Foreground(accent).Bold(true),
		option:       lipgloss.NewStyle().PaddingLeft(2),
		optionActive: lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("#0b1215")).Background(accent).Bold(true),
		description:  lipgloss.NewStyle().Foreground(muted).PaddingLeft(4),
		help:         lipgloss.NewStyle().Faint(true),
		key:          lipgloss.NewStyle().Foreground(accent).Bold(true),
		prefixActive: lipgloss.NewStyle().Foreground(accent).Render("❯"),
		prefixInactive: lipgloss.NewStyle().
			Foreground(muted).Render("•"),
	}
}

func (t wizardTheme) keyCap(k string) string {
	return t.key.Render(k)
}

type wizardOption struct {
	label string
	desc  string
	hot   string
	mount bool
	scope configstore.ScopeChoice
}

type wizardModel struct {
	theme   wizardTheme
	cmd     string
	hostDir string
	project string
	version string
	logo    string

	cursor  int
	options []wizardOption
	result  wizardResult
	done    bool
	err     error

	shimmerColors []string
	shimmerPhase  int
}

func newWizardModel(cmd, hostDir, project, version string, theme wizardTheme, logo string) *wizardModel {
	projectName := strings.TrimSpace(filepath.Base(project))
	if projectName == "" || projectName == "." || projectName == string(filepath.Separator) {
		projectName = project
	}

	opts := []wizardOption{
		{
			label: "Always",
			desc:  "Mount for every session globally.",
			hot:   "1",
			mount: true,
			scope: configstore.ScopeChoiceGlobal,
		},
		{
			label: "This project only",
			desc:  fmt.Sprintf("Remember for %s.", projectName),
			hot:   "2",
			mount: true,
			scope: configstore.ScopeChoiceProject,
		},
		{
			label: "Just this once",
			desc:  "Mount now and ask again next time.",
			hot:   "3",
			mount: true,
			scope: configstore.ScopeChoiceOnce,
		},
		{
			label: "Skip mount",
			desc:  "",
			hot:   "4",
			mount: false,
			scope: configstore.ScopeChoiceOnce,
		},
	}

	var colors []string
	if theme.color {
		colors = []string{"#7C3AED", "#C026D3", "#FF1493"}
	}

	return &wizardModel{
		theme:         theme,
		cmd:           cmd,
		hostDir:       hostDir,
		project:       projectName,
		version:       version,
		logo:          logo,
		cursor:        2, // default to "Just this once"
		options:       opts,
		result:        wizardResult{mount: false, scope: configstore.ScopeChoiceOnce},
		shimmerColors: colors,
	}
}

func (m *wizardModel) Init() tea.Cmd {
	if len(m.shimmerColors) > 0 {
		return m.nextShimmerTick()
	}
	return nil
}

func (m *wizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		key := strings.ToLower(msg.String())
		switch key {
		case "ctrl+c":
			m.setResult(len(m.options) - 1)
			return m, tea.Quit
		case "esc":
			m.cursor = len(m.options) - 1
			m.setResult(len(m.options) - 1)
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
		case "enter":
			m.setResult(m.cursor)
			return m, tea.Quit
		case "y":
			index := m.cursor
			if !m.options[index].mount {
				index = m.firstMountIndex()
			}
			m.setResult(index)
			return m, tea.Quit
		case "n":
			m.setResult(len(m.options) - 1)
			return m, tea.Quit
		case "1", "2", "3", "4":
			idx := int(key[0] - '1')
			if idx >= 0 && idx < len(m.options) {
				m.cursor = idx
				m.setResult(idx)
				return m, tea.Quit
			}
		}
	case tea.QuitMsg:
		m.done = true
		return m, nil
	case shimmerMsg:
		if len(m.shimmerColors) > 0 {
			m.shimmerPhase = (m.shimmerPhase + 1) % len([]rune(fmt.Sprintf("Welcome to Leash %s", m.version)))
			return m, m.nextShimmerTick()
		}
		return m, nil
	}
	return m, nil
}

func (m *wizardModel) View() string {
	title := m.renderTitle()
	subtitle := m.theme.subtitle.Render("Volume Mount Wizard")

	body := []string{
		fmt.Sprintf("%s %s", m.theme.label.Render("Command        :"), m.theme.value.Render(m.cmd)),
		fmt.Sprintf("%s %s", m.theme.label.Render("Project        :"), m.theme.value.Render(m.project)),
		fmt.Sprintf("%s %s", m.theme.label.Render("Proposed mount :"), m.theme.value.Render(m.hostDir)),
		"",
	}

	for i, opt := range m.options {
		number := fmt.Sprintf("%d.", i+1)
		labelLine := fmt.Sprintf("%s %s", number, opt.label)
		if i == m.cursor {
			body = append(body, m.theme.optionActive.Render("  "+labelLine+" "))
		} else {
			body = append(body, m.theme.option.Render("  "+labelLine))
		}
		body = append(body, m.theme.description.Render(opt.desc))
		body = append(body, "")
	}

	help := fmt.Sprintf("Use ↑/↓ or press %s–%s. Enter selects; Esc skips.",
		m.theme.keyCap("1"), m.theme.keyCap("4"))
	body = append(body, m.theme.help.Render(help), "")

	center := lipgloss.NewStyle().Width(wizardInnerWidth).Align(lipgloss.Center)

	rows := []string{}
	if logo := m.renderLogo(); logo != "" {
		rows = append(rows, center.Render(""))
		rows = append(rows, center.Render(logo))
	}
	rows = append(rows,
		center.Render(""),
		center.Render(title),
		center.Render(subtitle),
		"",
		lipgloss.JoinVertical(lipgloss.Left, body...),
	)

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)
	lines := strings.Split(content, "\n")

	cardLines := make([]string, 0, len(lines)+2)
	cardLines = append(cardLines, m.renderBorderLine("╭", "─", "╮"))
	for _, line := range lines {
		cardLines = append(cardLines, m.renderContentLine(line))
	}
	cardLines = append(cardLines, m.renderBorderLine("╰", "─", "╯"))

	return "\n" + strings.Join(cardLines, "\n") + "\n"
}

func (m *wizardModel) setResult(index int) {
	if index < 0 || index >= len(m.options) {
		return
	}
	opt := m.options[index]
	m.result = wizardResult{
		mount: opt.mount,
		scope: opt.scope,
	}
	m.cursor = index
	m.done = true
}

func (m *wizardModel) firstMountIndex() int {
	for i, opt := range m.options {
		if opt.mount {
			return i
		}
	}
	return 0
}

type shimmerMsg struct{}

func (m *wizardModel) nextShimmerTick() tea.Cmd {
	return tea.Tick(280*time.Millisecond, func(time.Time) tea.Msg {
		return shimmerMsg{}
	})
}

func (m *wizardModel) renderTitle() string {
	base := fmt.Sprintf("Welcome to Leash %s", m.version)
	if len(m.shimmerColors) == 0 {
		return m.theme.title.Render(base)
	}

	runes := []rune(base)
	styled := make([]string, len(runes))
	n := len(runes)
	gradient := m.shimmerColors
	lead := m.shimmerPhase % n
	trailLen := len(gradient)
	start := (lead - (trailLen - 1) + n) % n
	for idx := 0; idx < trailLen; idx++ {
		pos := (start + idx) % n
		color := gradient[idx]
		styled[pos] = lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(string(runes[pos]))
	}
	for idx := 1; idx < trailLen; idx++ {
		pos := (lead + idx) % n
		color := gradient[trailLen-idx-1]
		styled[pos] = lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(string(runes[pos]))
	}
	for i, r := range runes {
		if styled[i] == "" {
			styled[i] = m.theme.title.Render(string(r))
		}
	}
	return strings.Join(styled, "")
}

func (m *wizardModel) renderLogo() string {
	cleaned := strings.TrimSpace(m.logo)
	if cleaned == "" {
		return ""
	}
	content := cleaned
	if !m.theme.color {
		content = stripANSI(content)
	}
	return content
}

func (m *wizardModel) renderBorderLine(left, fill, right string) string {
	fillRune := []rune(fill)
	if len(fillRune) == 0 {
		fillRune = []rune(" ")
	}

	leftPart, rightPart := left, right
	if m.theme.color && m.theme.accentColor != "" {
		accentStyle := lipgloss.NewStyle().Foreground(m.theme.accentColor)
		leftPart = accentStyle.Render(left)
		rightPart = accentStyle.Render(right)
	}

	if !m.theme.color || len(m.shimmerColors) == 0 || m.theme.accentColor == "" {
		return leftPart + strings.Repeat(string(fillRune[0]), wizardCardWidth) + rightPart
	}

	accentStyle := lipgloss.NewStyle().Foreground(m.theme.accentColor)
	gradient := m.shimmerColors
	trailLen := len(gradient)

	styled := make([]string, wizardCardWidth)
	for i := 0; i < wizardCardWidth; i++ {
		styled[i] = accentStyle.Render(string(fillRune[0]))
	}

	title := fmt.Sprintf("Welcome to Leash %s", m.version)
	titleRunes := []rune(title)
	if len(titleRunes) == 0 {
		return leftPart + strings.Join(styled, "") + rightPart
	}

	pad := 0
	if wizardInnerWidth > len(titleRunes) {
		pad = (wizardInnerWidth - len(titleRunes)) / 2
	}
	lead := m.shimmerPhase % len(titleRunes)
	highlightPos := 2 + pad + lead

	for idx := 0; idx < trailLen; idx++ {
		pos := highlightPos - (trailLen - 1 - idx)
		if pos < 0 || pos >= wizardCardWidth {
			continue
		}
		styled[pos] = lipgloss.NewStyle().
			Foreground(lipgloss.Color(gradient[idx])).
			Render(string(fillRune[0]))
	}
	for idx := 1; idx < trailLen; idx++ {
		pos := highlightPos + idx
		if pos < 0 || pos >= wizardCardWidth {
			break
		}
		styled[pos] = lipgloss.NewStyle().
			Foreground(lipgloss.Color(gradient[trailLen-idx-1])).
			Render(string(fillRune[0]))
	}

	return leftPart + strings.Join(styled, "") + rightPart
}

func (m *wizardModel) renderContentLine(inner string) string {
	width := lipgloss.Width(inner)
	if width < wizardInnerWidth {
		inner = inner + strings.Repeat(" ", wizardInnerWidth-width)
	}
	padding := strings.Repeat(" ", 2)

	leftBorder := "│"
	rightBorder := "│"
	if m.theme.color && m.theme.accentColor != "" {
		borderStyle := lipgloss.NewStyle().Foreground(m.theme.accentColor)
		leftBorder = borderStyle.Render("│")
		rightBorder = borderStyle.Render("│")
	}

	return leftBorder + padding + inner + padding + rightBorder
}

func stripANSI(s string) string {
	var b strings.Builder
	runes := []rune(s)
	skip := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if skip {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				skip = false
			}
			continue
		}
		if r == 0x1b {
			skip = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func prepareLogo(raw string, color bool) string {
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.ReplaceAll(raw, "\x1b[2J", "")
	raw = strings.ReplaceAll(raw, "\x1b[H", "")
	trimmed := strings.Trim(raw, "\n")
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	if color {
		return strings.Join(lines, "\n")
	}
	for i, line := range lines {
		lines[i] = stripANSI(line)
	}
	return strings.Join(lines, "\n")
}

func canUseBubbleTea(in io.Reader, out io.Writer) bool {
	type fd interface {
		Fd() uintptr
	}
	_, okIn := in.(fd)
	_, okOut := out.(fd)
	return okIn && okOut
}
