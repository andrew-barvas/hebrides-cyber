import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import OnboardingChecklist from "./OnboardingChecklist";

const allDone = {
  verifiedDomain: true,
  hasScanned: true,
  hasReport: true,
  hasAlertChannel: true,
  alertChannelIsSlackTeams: false,
};

beforeEach(() => {
  localStorage.clear();
});

describe("OnboardingChecklist", () => {
  it("renders nothing once every step is complete", () => {
    const { container } = render(<OnboardingChecklist {...allDone} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the incomplete steps with an undone marker and an action link", () => {
    render(<OnboardingChecklist {...allDone} verifiedDomain={false} hasAlertChannel={false} />);

    expect(screen.getByText(/Verify a domain you own/)).toBeInTheDocument();
    expect(screen.getByText("○ Verify a domain you own")).toBeInTheDocument();
    expect(screen.getByText("Verify below")).toBeInTheDocument();
  });

  it("shows a done step without an action link", () => {
    render(<OnboardingChecklist {...allDone} verifiedDomain={false} />);

    expect(screen.getByText("✓ Run your first scan")).toBeInTheDocument();
    expect(screen.queryByText("Run one below")).not.toBeInTheDocument();
  });

  it("shows the progress count", () => {
    render(<OnboardingChecklist {...allDone} verifiedDomain={false} hasAlertChannel={false} />);
    expect(screen.getByText(/2\/4/)).toBeInTheDocument();
  });

  it("labels the alert step for Slack/Teams plans differently than for others", () => {
    const { rerender } = render(<OnboardingChecklist {...allDone} hasAlertChannel={false} alertChannelIsSlackTeams={true} />);
    expect(screen.getByText(/Connect Slack or Teams for alerts/)).toBeInTheDocument();

    rerender(<OnboardingChecklist {...allDone} hasAlertChannel={false} alertChannelIsSlackTeams={false} />);
    expect(screen.getByText(/Set up a webhook for alerts/)).toBeInTheDocument();
  });

  it("dismisses and persists the dismissal across a re-mount", () => {
    const { unmount } = render(<OnboardingChecklist {...allDone} verifiedDomain={false} />);
    fireEvent.click(screen.getByText("Dismiss"));
    expect(screen.queryByText(/Verify a domain you own/)).not.toBeInTheDocument();
    unmount();

    const { container } = render(<OnboardingChecklist {...allDone} verifiedDomain={false} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("does not render for a returning visitor who already dismissed it in a prior session", () => {
    localStorage.setItem("onboarding-checklist-dismissed", "1");
    const { container } = render(<OnboardingChecklist {...allDone} verifiedDomain={false} />);
    expect(container).toBeEmptyDOMElement();
  });
});
