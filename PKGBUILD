# Maintainer: FirmaDigitaleOpen <firmadigitaleopen@example.invalid>
#
# Build notes:
#   - The Bit4id PKCS#11 module (libbit4xpki.so) is proprietary and NOT in git;
#     it is bundled into the package only when present next to the repo at
#     tarball time. Without it CMake still builds and installs, just skipping
#     the whole token bundle (the configure output says so with a WARNING).
#   - Prepare the source tarball from a local checkout:
#       tar --exclude=.git --exclude=build --exclude=build-* \
#           --exclude='*.deb' --exclude='_CPack_Packages' \
#           -czf firmadigitaleopen-1.0.0.tar.gz .
#   - The ctest suites need untracked fixture data (tests/data/test.pdf etc.)
#     that git does not ship, so the suite is NOT run by makepkg. Use the
#     repo's Dockerfile (--target test) for a full build+test instead.

pkgname=firmadigitaleopen
pkgver=1.0.0
pkgrel=1
pkgdesc="Firma digitale PAdES (PDF) e P7M con token PKCS#11"
arch=('x86_64' 'aarch64')
url="https://example.invalid/firmadigitaleopen"
license=('custom')
depends=('qt6-base' 'poppler-qt6' 'openssl' 'libxml2')
makedepends=('cmake' 'ninja')
install=firmadigitaleopen.install
source=("firmadigitaleopen-$pkgver.tar.gz")
md5sums=('SKIP')

build() {
    cmake -S "$srcdir/$pkgname-$pkgver" -B build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build
}

package() {
    DESTDIR="$pkgdir" cmake --install build
}