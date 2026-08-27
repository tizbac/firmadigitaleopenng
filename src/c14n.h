#pragma once

#include <functional>
#include <vector>

struct _xmlNode;
typedef struct _xmlNode xmlNode;

namespace fdo {

// W3C Exclusive XML Canonicalization (http://www.w3.org/2001/10/xml-exc-c14n#).
//
// Namespace declarations are re-emitted at the point of first use along
// each output path (the behavior of lxml c14n2 / signxml and of the
// producer of the AgID TSL; verified byte-for-byte against reference
// vectors in tests/tst_c14n.cpp).
//
// `root` is the topmost element of the node-set. `visible` optionally
// prunes whole subtrees (e.g. the enveloped-signature transform: reject
// the ds:Signature element). A node that is not visible is skipped
// together with its whole subtree.
class C14N
{
public:
    using Visibility = std::function<bool(const xmlNode *)>;

    static std::vector<unsigned char> canonicalize(const xmlNode *root,
                                                   const Visibility &visible = nullptr);
};

} // namespace fdo
