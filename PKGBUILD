# Maintainer: FirmaDigitaleOpen <firmadigitaleopen@example.invalid>
#
# Build notes:
#   - Source is the git remote configured in .git/config, cloned over SSH via
#     the git+ssh:// scheme. The Bit4id PKCS#11 module (libbit4xpki.so) IS in
#     git, so the clone carries it and CMake bundles it into the package; if
#     it is ever missing again the configure output says so with a WARNING and
#     the build just skips the whole token bundle.
#   - The ctest suites need untracked fixture data (tests/data/test.pdf etc.)
#     that git does not ship, so the suite is NOT run by makepkg. Use the
#     repo's Dockerfile (--target test) for a full build+test instead.

pkgname=firmadigitaleopen
pkgver=1.0.0
pkgrel=1
pkgdesc="Firma digitale PAdES (PDF) e P7M con token PKCS#11"
arch=('x86_64')
url="https://github.com/tizbac/firmadigitaleopenng"
license=('custom')
depends=('qt6-base' 'poppler-qt6' 'openssl' 'libxml2')
makedepends=('cmake' 'ninja' 'git')
# makepkg strips binaries by default, but stripping libbit4xpki.so breaks it
# (C_Initialize fails with CKR_GENERAL_ERROR). Never strip this module.
options=('!strip')
install=firmadigitaleopen.install
source=("git+https://github.com/tizbac/firmadigitaleopenng.git")
md5sums=('SKIP')

build() {
    cmake -S "$srcdir/firmadigitaleopencpp" -B build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build
}

package() {
    DESTDIR="$pkgdir" cmake --install build
}
