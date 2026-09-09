// swift-tools-version: 6.2
// B267 spike: a throwaway helper that boots one Linux container VM on the
// Containerization Swift package, from a kernel k3sm built itself and a rootfs
// ext4 image k3sm built from its own unpacked OCI tree. Not shipped.
import PackageDescription

let package = Package(
    name: "cvmspike",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", exact: "0.45.0")
    ],
    targets: [
        .executableTarget(
            name: "cvmspike",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationEXT4", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
                .product(name: "ContainerizationArchive", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
            ]
        )
    ]
)
