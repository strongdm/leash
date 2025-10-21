import SwiftUI

struct ExperimentalSettingsView: View {
    @State private var filterPreferences = NetworkFilterManager.FilterPreferences()
    @State private var lastCommittedFilterPreferences = NetworkFilterManager.FilterPreferences()
    @State private var filterPreferencesLoading = true
    @State private var updatingFilterPreferences = false
    @State private var filterPreferencesError: String?
    @State private var showSystemWideAlert = false
    @State private var pendingSystemWideActivation = false
    @State private var suspendPreferenceUpdates = false
    @State private var needsPreferenceResync = false

    var body: some View {
        Form {
            Section("Flow Evaluation") {
                Toggle(isOn: $filterPreferences.systemWideEnforcement) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Enforce rules for untracked processes")
                            .font(.system(size: 13, weight: .medium))
                        Text("When enabled, Leash evaluates flows missing PID metadata using proc lookups (affects Safari and other system apps).")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .disabled(filterPreferencesLoading || updatingFilterPreferences)
                .onChange(of: filterPreferences.systemWideEnforcement, perform: handleSystemWideToggleChange)

                Toggle(isOn: $filterPreferences.flowDelayEnabled) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Delay new flows before evaluation")
                            .font(.system(size: 13, weight: .medium))
                        Text("Adds a short random pause so PID metadata can arrive before decisions are made.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .disabled(filterPreferencesLoading || updatingFilterPreferences)
                .onChange(of: filterPreferences.flowDelayEnabled) { _ in
                    schedulePreferenceUpdate()
                }

                if filterPreferences.flowDelayEnabled {
                    VStack(alignment: .leading, spacing: 6) {
                        Stepper(
                            value: Binding(
                                get: { filterPreferences.flowDelayMin },
                                set: { newValue in updateFlowDelayMin(newValue) }
                            ),
                            in: FlowDelayLimits.lowerBound...FlowDelayLimits.upperBound,
                            step: FlowDelayLimits.step
                        ) {
                            Text("Minimum delay: \(formattedDelay(filterPreferences.flowDelayMin))")
                                .font(.system(size: 12))
                        }

                        Stepper(
                            value: Binding(
                                get: { filterPreferences.flowDelayMax },
                                set: { newValue in updateFlowDelayMax(newValue) }
                            ),
                            in: FlowDelayLimits.lowerBound...FlowDelayLimits.upperBound,
                            step: FlowDelayLimits.step
                        ) {
                            Text("Maximum delay: \(formattedDelay(filterPreferences.flowDelayMax))")
                                .font(.system(size: 12))
                        }

                        Text("Active range: \(formattedDelay(filterPreferences.flowDelayMin)) – \(formattedDelay(filterPreferences.flowDelayMax))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.leading, 4)
                }
            }

            if filterPreferencesLoading {
                ProgressView()
                    .controlSize(.small)
            }

            if updatingFilterPreferences {
                Text("Updating filter preferences…")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }

            if let filterPreferencesError {
                Text(filterPreferencesError)
                    .font(.system(size: 11))
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(24)
        .frame(minWidth: 360)
        .onAppear {
            refreshFilterPreferences()
        }
        .alert("Enable System-wide Enforcement?", isPresented: $showSystemWideAlert) {
            Button("Cancel", role: .cancel) {
                pendingSystemWideActivation = false
            }
            Button("Enable", role: .destructive) {
                guard pendingSystemWideActivation else { return }
                pendingSystemWideActivation = false
                suspendPreferenceUpdates = true
                filterPreferences.systemWideEnforcement = true
                suspendPreferenceUpdates = false
                schedulePreferenceUpdate()
            }
        } message: {
            Text("When enabled, Leash will enforce network rules for any process, even if PID metadata is missing. This can block or audit native apps like Safari. Continue?")
        }
    }
}

private extension ExperimentalSettingsView {
    enum FlowDelayLimits {
        static let lowerBound: Double = 0.0
        static let upperBound: Double = 1.0
        static let step: Double = 0.05
    }

    func refreshFilterPreferences() {
        filterPreferencesLoading = true
        filterPreferencesError = nil
        Task {
            let preferences = await NetworkFilterManager.shared.currentFilterPreferences()
            await MainActor.run {
                suspendPreferenceUpdates = true
                filterPreferences = preferences
                lastCommittedFilterPreferences = preferences
                suspendPreferenceUpdates = false
                filterPreferencesLoading = false
            }
        }
    }

    func handleSystemWideToggleChange(_ newValue: Bool) {
        guard !suspendPreferenceUpdates else { return }
        guard !filterPreferencesLoading else { return }

        if newValue && !lastCommittedFilterPreferences.systemWideEnforcement {
            pendingSystemWideActivation = true
            suspendPreferenceUpdates = true
            filterPreferences.systemWideEnforcement = lastCommittedFilterPreferences.systemWideEnforcement
            suspendPreferenceUpdates = false
            showSystemWideAlert = true
            return
        }

        if newValue == lastCommittedFilterPreferences.systemWideEnforcement {
            return
        }

        schedulePreferenceUpdate()
    }

    func updateFlowDelayMin(_ newValue: Double) {
        guard !suspendPreferenceUpdates else { return }
        let clamped = min(max(newValue, FlowDelayLimits.lowerBound), FlowDelayLimits.upperBound)
        suspendPreferenceUpdates = true
        filterPreferences.flowDelayMin = clamped
        if filterPreferences.flowDelayMin > filterPreferences.flowDelayMax {
            filterPreferences.flowDelayMax = filterPreferences.flowDelayMin
        }
        suspendPreferenceUpdates = false
        schedulePreferenceUpdate()
    }

    func updateFlowDelayMax(_ newValue: Double) {
        guard !suspendPreferenceUpdates else { return }
        let lowerBound = max(filterPreferences.flowDelayMin, FlowDelayLimits.lowerBound)
        let clamped = min(max(newValue, lowerBound), FlowDelayLimits.upperBound)
        suspendPreferenceUpdates = true
        filterPreferences.flowDelayMax = clamped
        suspendPreferenceUpdates = false
        schedulePreferenceUpdate()
    }

    func schedulePreferenceUpdate() {
        guard !filterPreferencesLoading else { return }
        guard !suspendPreferenceUpdates else { return }

        var normalized = filterPreferences.normalized()
        if normalized.flowDelayMin > normalized.flowDelayMax {
            normalized.flowDelayMax = normalized.flowDelayMin
        }

        if normalized != filterPreferences {
            suspendPreferenceUpdates = true
            filterPreferences = normalized
            suspendPreferenceUpdates = false
        }

        guard normalized != lastCommittedFilterPreferences else { return }

        if updatingFilterPreferences {
            needsPreferenceResync = true
            return
        }

        applyFilterPreferences(normalized)
    }

    func applyFilterPreferences(_ preferences: NetworkFilterManager.FilterPreferences) {
        updatingFilterPreferences = true
        filterPreferencesError = nil

        Task {
            do {
                try await NetworkFilterManager.shared.updateFilterPreferences(preferences)
                await MainActor.run {
                    lastCommittedFilterPreferences = preferences
                    updatingFilterPreferences = false
                    if needsPreferenceResync {
                        needsPreferenceResync = false
                        schedulePreferenceUpdate()
                    }
                }
            } catch {
                let message = error.localizedDescription
                await MainActor.run {
                    filterPreferencesError = message
                    suspendPreferenceUpdates = true
                    filterPreferences = lastCommittedFilterPreferences
                    suspendPreferenceUpdates = false
                    updatingFilterPreferences = false
                    needsPreferenceResync = false
                }
            }
        }
    }

    func formattedDelay(_ seconds: Double) -> String {
        let milliseconds = Int((seconds * 1000).rounded())
        return "\(milliseconds) ms"
    }
}

struct LeashSettingsContainerView: View {
    var body: some View {
        TabView {
            ExperimentalSettingsView()
                .tabItem {
                    Label("Experimental Settings", systemImage: "cat")
                }
        }
    }
}
