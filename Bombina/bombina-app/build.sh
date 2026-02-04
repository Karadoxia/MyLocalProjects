#!/bin/bash
# Bombina Build Script
# Build cross-platform Bombina application

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🐸 Bombina Build Script${NC}"
echo "========================="

# Check prerequisites
check_prereqs() {
    echo -e "\n${YELLOW}Checking prerequisites...${NC}"
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Rust not found. Install from https://rustup.rs${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Rust installed: $(rustc --version)${NC}"
    
    # Check Dioxus CLI (optional)
    if command -v dx &> /dev/null; then
        echo -e "${GREEN}✓ Dioxus CLI installed${NC}"
    else
        echo -e "${YELLOW}⚠ Dioxus CLI not found. Install with: cargo install dioxus-cli${NC}"
    fi
}

# Build desktop app
build_desktop() {
    echo -e "\n${YELLOW}Building Desktop App...${NC}"
    
    if [ "$1" == "--release" ]; then
        cargo build --release --package bombina-desktop
        echo -e "${GREEN}✓ Release build complete: target/release/bombina${NC}"
    else
        cargo build --package bombina-desktop
        echo -e "${GREEN}✓ Debug build complete: target/debug/bombina${NC}"
    fi
}

# Run desktop app
run_desktop() {
    echo -e "\n${YELLOW}Running Desktop App...${NC}"
    
    if [ "$1" == "--release" ]; then
        cargo run --release --package bombina-desktop
    else
        cargo run --package bombina-desktop
    fi
}

# Run tests
run_tests() {
    echo -e "\n${YELLOW}Running Tests...${NC}"
    cargo test --workspace
    echo -e "${GREEN}✓ All tests passed${NC}"
}

# Check code
check_code() {
    echo -e "\n${YELLOW}Checking Code...${NC}"
    cargo fmt --check
    cargo clippy -- -D warnings
    echo -e "${GREEN}✓ Code check passed${NC}"
}

# Format code
format_code() {
    echo -e "\n${YELLOW}Formatting Code...${NC}"
    cargo fmt
    echo -e "${GREEN}✓ Code formatted${NC}"
}

# Clean build
clean() {
    echo -e "\n${YELLOW}Cleaning Build...${NC}"
    cargo clean
    echo -e "${GREEN}✓ Clean complete${NC}"
}

# Show help
show_help() {
    echo "
Usage: ./build.sh [COMMAND] [OPTIONS]

Commands:
    check       Check prerequisites
    build       Build desktop app (add --release for release build)
    run         Run desktop app (add --release for release build)
    test        Run all tests
    lint        Check code formatting and lint
    fmt         Format code
    clean       Clean build artifacts
    help        Show this help message

Examples:
    ./build.sh build
    ./build.sh build --release
    ./build.sh run
    ./build.sh test
"
}

# Main
case "${1:-help}" in
    check)
        check_prereqs
        ;;
    build)
        check_prereqs
        build_desktop "$2"
        ;;
    run)
        check_prereqs
        run_desktop "$2"
        ;;
    test)
        run_tests
        ;;
    lint)
        check_code
        ;;
    fmt)
        format_code
        ;;
    clean)
        clean
        ;;
    help|*)
        show_help
        ;;
esac

echo -e "\n${GREEN}Done!${NC}"
