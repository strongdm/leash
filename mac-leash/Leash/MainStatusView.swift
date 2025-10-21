import SwiftUI
import AppKit
import NetworkExtension
import os.log

struct MainStatusView: View {
    @ObservedObject var endpointSecurityController: SystemExtensionController
    @ObservedObject var networkExtensionController: SystemExtensionController
    @State var networkFilterStatus: FilterStatus = .loading
    @State var apiStatus: APIStatus = .loading

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("Leash")
                    .font(.system(size: 18, weight: .semibold))

                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            ScrollView {
                VStack(spacing: 16) {
                    endpointSecuritySection
                    networkFilterSection
                    webInterfaceSection
                }
                .padding(20)
            }
        }
        .frame(minWidth: 400, minHeight: 450)
        .onAppear {
            Task { @MainActor in
                endpointSecurityController.ensureExtensionIsActive()
                networkExtensionController.ensureExtensionIsActive()
            }
            refreshNetworkFilterStatus()
            checkAPIStatus()
        }
    }
}
