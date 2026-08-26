// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "ElmPay", platforms: [.iOS(.v15), .macOS(.v12)], products: [.library(name: "ElmPay", targets: ["ElmPay"])], targets: [.target(name: "ElmPay"), .testTarget(name: "ElmPayTests", dependencies: ["ElmPay"])])
