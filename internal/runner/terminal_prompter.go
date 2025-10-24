package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/strongdm/leash/internal/configstore"
	"golang.org/x/term"
)

type terminalPrompter struct {
	in          *bufio.Reader
	out         io.Writer
	color       bool
	accentColor string
}

func newTerminalPrompter(in io.Reader, out io.Writer) *terminalPrompter {
	p := &terminalPrompter{
		in:          bufio.NewReader(in),
		out:         out,
		color:       supportsColor(out),
		accentColor: "\033[38;5;205m",
	}
	return p
}

func (p *terminalPrompter) ConfirmMount(ctx context.Context, cmd, hostDir string) (bool, error) {
	if err := p.renderMountIntro(cmd, hostDir); err != nil {
		return false, err
	}

	question := fmt.Sprintf("%s %s %s ", p.promptArrow(), p.bold("Mount this directory inside the container?"), p.muted("[Y/n]"))

	for {
		if _, err := fmt.Fprint(p.out, question); err != nil {
			return false, err
		}
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		normalized := strings.ToLower(strings.TrimSpace(line))
		switch normalized {
		case "", "n", "no":
			return false, nil
		case "y", "yes":
			return true, nil
		default:
			if _, err := fmt.Fprintf(p.out, "%s Please respond with %s or %s.\n", p.muted("•"), p.bold("y"), p.bold("n")); err != nil {
				return false, err
			}
		}
	}
}

func (p *terminalPrompter) ChooseScope(ctx context.Context, cmd, cwd string) (configstore.ScopeChoice, error) {
	if err := p.renderScopeIntro(cmd, cwd); err != nil {
		return 0, err
	}

	prompt := fmt.Sprintf("%s Select an option [1-3]: ", p.promptArrow())
	for {
		if _, err := fmt.Fprint(p.out, prompt); err != nil {
			return 0, err
		}
		line, err := p.readLine()
		if err != nil {
			return 0, err
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		switch strings.TrimSpace(line) {
		case "1":
			return configstore.ScopeChoiceGlobal, nil
		case "2":
			return configstore.ScopeChoiceProject, nil
		case "3":
			return configstore.ScopeChoiceOnce, nil
		default:
			if _, err := fmt.Fprintf(p.out, "%s Please enter %s, %s, or %s.\n", p.muted("•"), p.bold("1"), p.bold("2"), p.bold("3")); err != nil {
				return 0, err
			}
		}
	}
}

func (p *terminalPrompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *terminalPrompter) renderMountIntro(cmd, hostDir string) error {
	if _, err := fmt.Fprintln(p.out); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(p.out, "%s %s\n", p.accent("╭"), p.bold("Mount access requested")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.out, "│ %s %s\n", p.label("Command"), p.accent(cmd)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.out, "│ %s %s\n", p.label("Directory"), hostDir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.out, "%s\n\n", p.accent("╰──────────────────────────────────────")); err != nil {
		return err
	}
	return nil
}

func (p *terminalPrompter) renderScopeIntro(cmd, cwd string) error {
	project := filepath.Base(cwd)
	if project == "" || project == string(os.PathSeparator) || project == "." {
		project = cwd
	}

	lines := []string{
		fmt.Sprintf("%s Decide how long to share %s", p.accent("╭"), p.bold(cmd)),
		fmt.Sprintf("│ %s %s", p.label("Project"), project),
		p.accent("╰──────────────────────────────────────"),
		fmt.Sprintf("  %s %s %s", p.number("1"), p.bold("Always"), p.muted("Share for every session")),
		fmt.Sprintf("  %s %s %s", p.number("2"), p.bold("Project"), p.muted(fmt.Sprintf("Only for %s", project))),
		fmt.Sprintf("  %s %s %s", p.number("3"), p.bold("Once"), p.muted("Just this run")),
		"",
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(p.out, line); err != nil {
			return err
		}
	}
	return nil
}

func (p *terminalPrompter) accent(text string) string {
	return p.wrap(p.accentColor, text)
}

func (p *terminalPrompter) bold(text string) string {
	return p.wrap("\033[1m", text)
}

func (p *terminalPrompter) muted(text string) string {
	return p.wrap("\033[2m", text)
}

func (p *terminalPrompter) label(text string) string {
	return p.muted(text + ":")
}

func (p *terminalPrompter) number(n string) string {
	return p.accent(n + ".")
}

func (p *terminalPrompter) promptArrow() string {
	if p.color {
		return p.accent("›")
	}
	return ">"
}

func (p *terminalPrompter) wrap(code, text string) string {
	if !p.color || code == "" {
		return text
	}
	return code + text + "\033[0m"
}

func supportsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	type fd interface {
		Fd() uintptr
	}
	f, ok := w.(fd)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
