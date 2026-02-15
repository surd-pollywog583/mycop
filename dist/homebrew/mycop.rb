class Mycop < Formula
  desc "AI-powered code security scanner"
  homepage "https://github.com/AbdumajidRashidov/mycop"
  version "0.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/AbdumajidRashidov/mycop/releases/download/v#{version}/mycop-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "mycop"
  end

  test do
    assert_match "mycop", shell_output("#{bin}/mycop --version")
  end
end
