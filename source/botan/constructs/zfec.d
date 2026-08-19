/**
* Forward error correction based on Vandermonde matrices (zfec)
*
* Copyright:
* (C) 1997-1998 Luigi Rizzo (luigi@iet.unipi.it)
* (C) 2009,2010,2021 Jack Lloyd
* (C) 2011 Billy Brumley (billy.brumley@aalto.fi)
* (C) 2014-2026 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.constructs.zfec;

import botan.constants;
static if (BOTAN_HAS_ZFEC):

import botan.utils.exceptn;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm : swap;

/// GF(2^8) with p(x) = 1+x^2+x^3+x^4+x^8 (C++ zfec.cpp).
private immutable ubyte[255] GF_EXP = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74, 0xE8, 0xCD, 0x87, 0x13, 0x26,
    0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75, 0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0,
    0x9D, 0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77, 0xEE, 0xC1, 0x9F, 0x23,
    0x46, 0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1,
    0x5F, 0xBE, 0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E, 0x3C, 0x78, 0xF0,
    0xFD, 0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F, 0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2,
    0xD9, 0xAF, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD, 0x67, 0xCE,
    0x81, 0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B, 0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC,
    0x85, 0x17, 0x2E, 0x5C, 0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A, 0x54,
    0xA8, 0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92, 0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73,
    0xE6, 0xD1, 0xBF, 0x63, 0xC6, 0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF,
    0xE3, 0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E, 0xDC, 0xA5, 0x57, 0xAE, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xC8, 0x8D, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6,
    0x51, 0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56, 0xAC, 0x45, 0x8A, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4, 0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16,
    0x2C, 0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E
];

private immutable ubyte[256] GF_LOG = [
    0xFF, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1A, 0xC6, 0x03, 0xDF, 0x33, 0xEE, 0x1B, 0x68, 0xC7, 0x4B,
    0x04, 0x64, 0xE0, 0x0E, 0x34, 0x8D, 0xEF, 0x81, 0x1C, 0xC1, 0x69, 0xF8, 0xC8, 0x08, 0x4C, 0x71,
    0x05, 0x8A, 0x65, 0x2F, 0xE1, 0x24, 0x0F, 0x21, 0x35, 0x93, 0x8E, 0xDA, 0xF0, 0x12, 0x82, 0x45,
    0x1D, 0xB5, 0xC2, 0x7D, 0x6A, 0x27, 0xF9, 0xB9, 0xC9, 0x9A, 0x09, 0x78, 0x4D, 0xE4, 0x72, 0xA6,
    0x06, 0xBF, 0x8B, 0x62, 0x66, 0xDD, 0x30, 0xFD, 0xE2, 0x98, 0x25, 0xB3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xD0, 0x94, 0xCE, 0x8F, 0x96, 0xDB, 0xBD, 0xF1, 0xD2, 0x13, 0x5C, 0x83, 0x38, 0x46, 0x40,
    0x1E, 0x42, 0xB6, 0xA3, 0xC3, 0x48, 0x7E, 0x6E, 0x6B, 0x3A, 0x28, 0x54, 0xFA, 0x85, 0xBA, 0x3D,
    0xCA, 0x5E, 0x9B, 0x9F, 0x0A, 0x15, 0x79, 0x2B, 0x4E, 0xD4, 0xE5, 0xAC, 0x73, 0xF3, 0xA7, 0x57,
    0x07, 0x70, 0xC0, 0xF7, 0x8C, 0x80, 0x63, 0x0D, 0x67, 0x4A, 0xDE, 0xED, 0x31, 0xC5, 0xFE, 0x18,
    0xE3, 0xA5, 0x99, 0x77, 0x26, 0xB8, 0xB4, 0x7C, 0x11, 0x44, 0x92, 0xD9, 0x23, 0x20, 0x89, 0x2E,
    0x37, 0x3F, 0xD1, 0x5B, 0x95, 0xBC, 0xCF, 0xCD, 0x90, 0x87, 0x97, 0xB2, 0xDC, 0xFC, 0xBE, 0x61,
    0xF2, 0x56, 0xD3, 0xAB, 0x14, 0x2A, 0x5D, 0x9E, 0x84, 0x3C, 0x39, 0x53, 0x47, 0x6D, 0x41, 0xA2,
    0x1F, 0x2D, 0x43, 0xD8, 0xB7, 0x7B, 0xA4, 0x76, 0xC4, 0x17, 0x49, 0xEC, 0x7F, 0x0C, 0x6F, 0xF6,
    0x6C, 0xA1, 0x3B, 0x52, 0x29, 0x9D, 0x55, 0xAA, 0xFB, 0x60, 0x86, 0xB1, 0xBB, 0xCC, 0x3E, 0x5A,
    0xCB, 0x59, 0x5F, 0xB0, 0x9C, 0xA9, 0xA0, 0x51, 0x0B, 0xF5, 0x16, 0xEB, 0x7A, 0x75, 0x2C, 0xD7,
    0x4F, 0xAE, 0xD5, 0xE9, 0xE6, 0xE7, 0xAD, 0xE8, 0x74, 0xD6, 0xF4, 0xEA, 0xA8, 0x50, 0x58, 0xAF
];

private immutable ubyte[256] GF_INVERSE = [
    0x00, 0x01, 0x8E, 0xF4, 0x47, 0xA7, 0x7A, 0xBA, 0xAD, 0x9D, 0xDD, 0x98, 0x3D, 0xAA, 0x5D, 0x96,
    0xD8, 0x72, 0xC0, 0x58, 0xE0, 0x3E, 0x4C, 0x66, 0x90, 0xDE, 0x55, 0x80, 0xA0, 0x83, 0x4B, 0x2A,
    0x6C, 0xED, 0x39, 0x51, 0x60, 0x56, 0x2C, 0x8A, 0x70, 0xD0, 0x1F, 0x4A, 0x26, 0x8B, 0x33, 0x6E,
    0x48, 0x89, 0x6F, 0x2E, 0xA4, 0xC3, 0x40, 0x5E, 0x50, 0x22, 0xCF, 0xA9, 0xAB, 0x0C, 0x15, 0xE1,
    0x36, 0x5F, 0xF8, 0xD5, 0x92, 0x4E, 0xA6, 0x04, 0x30, 0x88, 0x2B, 0x1E, 0x16, 0x67, 0x45, 0x93,
    0x38, 0x23, 0x68, 0x8C, 0x81, 0x1A, 0x25, 0x61, 0x13, 0xC1, 0xCB, 0x63, 0x97, 0x0E, 0x37, 0x41,
    0x24, 0x57, 0xCA, 0x5B, 0xB9, 0xC4, 0x17, 0x4D, 0x52, 0x8D, 0xEF, 0xB3, 0x20, 0xEC, 0x2F, 0x32,
    0x28, 0xD1, 0x11, 0xD9, 0xE9, 0xFB, 0xDA, 0x79, 0xDB, 0x77, 0x06, 0xBB, 0x84, 0xCD, 0xFE, 0xFC,
    0x1B, 0x54, 0xA1, 0x1D, 0x7C, 0xCC, 0xE4, 0xB0, 0x49, 0x31, 0x27, 0x2D, 0x53, 0x69, 0x02, 0xF5,
    0x18, 0xDF, 0x44, 0x4F, 0x9B, 0xBC, 0x0F, 0x5C, 0x0B, 0xDC, 0xBD, 0x94, 0xAC, 0x09, 0xC7, 0xA2,
    0x1C, 0x82, 0x9F, 0xC6, 0x34, 0xC2, 0x46, 0x05, 0xCE, 0x3B, 0x0D, 0x3C, 0x9C, 0x08, 0xBE, 0xB7,
    0x87, 0xE5, 0xEE, 0x6B, 0xEB, 0xF2, 0xBF, 0xAF, 0xC5, 0x64, 0x07, 0x7B, 0x95, 0x9A, 0xAE, 0xB6,
    0x12, 0x59, 0xA5, 0x35, 0x65, 0xB8, 0xA3, 0x9E, 0xD2, 0xF7, 0x62, 0x5A, 0x85, 0x7D, 0xA8, 0x3A,
    0x29, 0x71, 0xC8, 0xF6, 0xF9, 0x43, 0xD7, 0xD6, 0x10, 0x73, 0x76, 0x78, 0x99, 0x0A, 0x19, 0x91,
    0x14, 0x3F, 0xE6, 0xF0, 0x86, 0xB1, 0xE2, 0xF1, 0xFA, 0x74, 0xF3, 0xB4, 0x6D, 0x21, 0xB2, 0x6A,
    0xE3, 0xE7, 0xB5, 0xEA, 0x03, 0x8F, 0xD3, 0xC9, 0x42, 0xD4, 0xE8, 0x75, 0x7F, 0xFF, 0x7E, 0xFD
];

private __gshared ubyte[] g_gf_mul;

private const(ubyte)* gfMulTable(ubyte y)
{
    if (g_gf_mul.length == 0)
    {
        g_gf_mul = new ubyte[256 * 256];
        foreach (i; 1 .. 256)
            foreach (j; 1 .. 256)
                g_gf_mul[256 * i + j] = GF_EXP[(GF_LOG[i] + GF_LOG[j]) % 255];
    }
    return &g_gf_mul[256 * y];
}

private void invertMatrix(ubyte[] matrix, size_t K)
{
    auto ipiv = new bool[K];
    auto indxc = new size_t[K];
    auto indxr = new size_t[K];

    foreach (col; 0 .. K)
    {
        size_t icol, irow;
        bool found = false;
        if (!ipiv[col] && matrix[col * K + col] != 0)
        {
            ipiv[col] = true;
            icol = col;
            irow = col;
            found = true;
        }
        else
        {
            foreach (row; 0 .. K)
            {
                if (ipiv[row])
                    continue;
                foreach (i; 0 .. K)
                {
                    if (!ipiv[i] && matrix[row * K + i] != 0)
                    {
                        ipiv[i] = true;
                        icol = row;
                        irow = i;
                        found = true;
                        break;
                    }
                }
                if (found)
                    break;
            }
        }
        if (!found)
            throw new InvalidArgument("ZFEC: pivot not found in invert_matrix");

        if (irow != icol)
        {
            foreach (i; 0 .. K)
                swap(matrix[irow * K + i], matrix[icol * K + i]);
        }

        indxr[col] = irow;
        indxc[col] = icol;
        ubyte* pivot_row = &matrix[icol * K];
        const ubyte c = pivot_row[icol];
        pivot_row[icol] = 1;
        if (c == 0)
            throw new InvalidArgument("ZFEC: singular matrix");
        if (c != 1)
        {
            const(ubyte)* mul_c = gfMulTable(GF_INVERSE[c]);
            foreach (i; 0 .. K)
                pivot_row[i] = mul_c[pivot_row[i]];
        }
        foreach (i; 0 .. K)
        {
            if (i == icol)
                continue;
            const ubyte z = matrix[i * K + icol];
            matrix[i * K + icol] = 0;
            const(ubyte)* mul_z = gfMulTable(z);
            foreach (j; 0 .. K)
                matrix[i * K + j] ^= mul_z[pivot_row[j]];
        }
    }

    foreach (i; 0 .. K)
    {
        if (indxr[i] != indxc[i])
        {
            foreach (row; 0 .. K)
                swap(matrix[row * K + indxr[i]], matrix[row * K + indxc[i]]);
        }
    }
}

private void createInvertedVdm(ubyte[] vdm, size_t K)
{
    if (K == 0)
        return;
    if (K == 1)
    {
        vdm[0] = 1;
        return;
    }
    auto b = new ubyte[K];
    auto c = new ubyte[K];
    c[K - 1] = 0;
    foreach (i; 1 .. K)
    {
        const(ubyte)* mul_p_i = gfMulTable(GF_EXP[i]);
        foreach (j; (K - 1 - (i - 1)) .. (K - 1))
            c[j] ^= mul_p_i[c[j + 1]];
        c[K - 1] ^= GF_EXP[i];
    }
    foreach (row; 0 .. K)
    {
        const(ubyte)* mul_p_row = gfMulTable(row == 0 ? 0 : GF_EXP[row]);
        ubyte t = 1;
        b[K - 1] = 1;
        size_t i = K - 1;
        while (i > 0)
        {
            b[i - 1] = cast(ubyte)(c[i] ^ mul_p_row[b[i]]);
            t = cast(ubyte)(b[i - 1] ^ mul_p_row[t]);
            --i;
        }
        const(ubyte)* mul_t_inv = gfMulTable(GF_INVERSE[t]);
        foreach (col; 0 .. K)
            vdm[col * K + row] = mul_t_inv[b[col]];
    }
}

/// One recovered/generated share (id + pointer). Used as decode input.
struct ZfecShare
{
    size_t id;
    const(ubyte)* data;
}

alias ZfecOutput = void delegate(size_t share, const(ubyte)* data, size_t len);

/**
* Tahoe-LAFS zfec compatible Vandermonde FEC.
* Not constant-time; the first K shares are the original input.
*/
final class ZFEC
{
public:
    /**
    * Params:
    *  K = number of shares needed to recover (1..255)
    *  N = total shares produced (K..255)
    */
    this(size_t K, size_t N)
    {
        if (K == 0 || N == 0 || K >= 256 || N >= 256 || K > N)
            throw new InvalidArgument("ZFEC: violated 1 <= K <= N < 256");
        m_K = K;
        m_N = N;
        m_enc_matrix = new ubyte[N * K];
        auto temp = new ubyte[N * K];
        createInvertedVdm(temp, K);
        foreach (i; K * K .. temp.length)
            temp[i] = GF_EXP[((i / K) * (i % K)) % 255];
        foreach (i; 0 .. K)
            m_enc_matrix[i * (K + 1)] = 1;
        foreach (row; K .. N)
        {
            foreach (col; 0 .. K)
            {
                ubyte acc = 0;
                foreach (i; 0 .. K)
                {
                    const ubyte row_v = temp[row * K + i];
                    const ubyte row_c = temp[col + K * i];
                    acc ^= gfMulTable(row_v)[row_c];
                }
                m_enc_matrix[row * K + col] = acc;
            }
        }
    }

    size_t recoveryThreshold() const { return m_K; }
    size_t generatedShares() const { return m_N; }
    string provider() const { return "base"; }

    void encode(const(ubyte)* input, size_t size, scope ZfecOutput output_cb) const
    {
        if (size % m_K != 0)
            throw new InvalidArgument("ZFEC::encode: input must be multiple of K uint8_ts");
        const size_t share_size = size / m_K;
        auto shares = new const(ubyte)*[m_K];
        foreach (i; 0 .. m_K)
            shares[i] = input + i * share_size;
        encodeShares(shares, share_size, output_cb);
    }

    void encodeShares(const(ubyte*)[] shares, size_t share_size, scope ZfecOutput output_cb) const
    {
        if (shares.length != m_K)
            throw new InvalidArgument("ZFEC::encode_shares must provide K shares");
        foreach (i; 0 .. m_K)
            output_cb(i, shares[i], share_size);
        auto fec_buf = new ubyte[share_size];
        foreach (i; m_K .. m_N)
        {
            linearCombination(fec_buf, shares, &m_enc_matrix[i * m_K], m_K, share_size);
            output_cb(i, fec_buf.ptr, fec_buf.length);
        }
    }

    void decodeShares(ZfecShare[] shares_in, size_t share_size, scope ZfecOutput output_cb) const
    {
        if (shares_in.length < m_K)
            throw new DecodingError("ZFEC: could not decode, less than K surviving shares");

        auto ordered = shares_in.dup;
        import std.algorithm : sort;
        sort!((a, b) => a.id < b.id)(ordered);

        auto decoding_matrix = new ubyte[m_K * m_K];
        auto indexes = new size_t[m_K];
        auto sharesv = new const(ubyte)*[m_K];

        size_t lo = 0;
        size_t hi = ordered.length;
        bool missing_primary = false;

        foreach (i; 0 .. m_K)
        {
            size_t share_id;
            const(ubyte)* share_data;
            if (lo < hi && ordered[lo].id == i)
            {
                share_id = ordered[lo].id;
                share_data = ordered[lo].data;
                ++lo;
            }
            else
            {
                --hi;
                share_id = ordered[hi].id;
                share_data = ordered[hi].data;
                missing_primary = true;
            }
            if (share_id >= m_N)
                throw new DecodingError("ZFEC: invalid share id detected during decode");
            if (share_id < m_K)
            {
                decoding_matrix[i * (m_K + 1)] = 1;
                output_cb(share_id, share_data, share_size);
            }
            else
                decoding_matrix[i * m_K .. i * m_K + m_K] = m_enc_matrix[share_id * m_K .. share_id * m_K + m_K];
            sharesv[i] = share_data;
            indexes[i] = share_id;
        }

        if (!missing_primary)
            return;

        invertMatrix(decoding_matrix, m_K);
        foreach (i; 0 .. indexes.length)
        {
            if (indexes[i] >= m_K)
            {
                auto buf = new ubyte[share_size];
                linearCombination(buf, sharesv, &decoding_matrix[i * m_K], m_K, share_size);
                output_cb(i, buf.ptr, share_size);
            }
        }
    }

private:
    static void addmul(ubyte* z, const(ubyte)* x, ubyte y, size_t size)
    {
        if (y == 0)
            return;
        const(ubyte)* mul = gfMulTable(y);
        while (size >= 16)
        {
            foreach (j; 0 .. 16)
                z[j] ^= mul[x[j]];
            x += 16;
            z += 16;
            size -= 16;
        }
        foreach (i; 0 .. size)
            z[i] ^= mul[x[i]];
    }

    static void linearCombination(ubyte[] z, const(ubyte*)[] x, const(ubyte)* y, size_t k, size_t size)
    {
        z[0 .. size] = 0;
        foreach (j; 0 .. k)
            addmul(z.ptr, x[j], y[j], size);
    }

    size_t m_K, m_N;
    ubyte[] m_enc_matrix;
}

static if (BOTAN_HAS_TESTS && !SKIP_ZFEC_TEST) unittest
{
    import botan.test;
    import botan.codec.hex;
    import botan.libstate.global_state;
    import memutils.hashmap;
    import std.stdio : File;
    import std.conv : to;

    auto state = globalState();
    logDebug("Testing zfec.d ...");
    size_t fails = 0;

    File vec = File("test_data/zfec.vec", "r");
    fails += runTestsBb(vec, "ZFEC", "Code", true,
        (ref HashMap!(string, string) m)
        {
            if (!("K" in m) || !("N" in m) || !("Data" in m) || !("Code" in m))
                return 0;
            const size_t K = to!size_t(m["K"]);
            const size_t N = to!size_t(m["N"]);
            auto input = hexDecode(m["Data"]);
            auto expected = hexDecode(m["Code"]);
            if (input.length % K != 0)
            {
                logError("zfec Data not multiple of K");
                return 1;
            }
            const size_t share_size = input.length / K;
            if (expected.length != share_size * (N - K))
            {
                logError("zfec Code length mismatch");
                return 1;
            }
            Unique!ZFEC zfec = new ZFEC(K, N);
            auto got = new ubyte[][N];
            bool[size_t] seen;
            zfec.encode(input.ptr, input.length,
                (size_t share, const(ubyte)* data, size_t len)
                {
                    if (share in seen)
                        throw new Exception("encode share twice");
                    seen[share] = true;
                    got[share] = data[0 .. len].dup;
                });
            if (seen.length != N)
            {
                logError("zfec encoded ", seen.length, " shares want ", N);
                return 1;
            }
            foreach (i; 0 .. N)
            {
                const(ubyte)* want = (i < K)
                    ? &input[share_size * i]
                    : &expected[share_size * (i - K)];
                if (got[i].length != share_size || got[i][] != want[0 .. share_size])
                {
                    logError("zfec encode share ", i, " mismatch");
                    return 1;
                }
            }

            size_t decodeCheck(ZfecShare[] subset)
            {
                bool[size_t] dec;
                zfec.decodeShares(subset, share_size,
                    (size_t share, const(ubyte)* data, size_t len)
                    {
                        if (share in dec)
                            throw new Exception("decode share twice");
                        if (share >= K || len != share_size
                            || data[0 .. len] != input[share * share_size .. share * share_size + share_size])
                            throw new Exception("decode share mismatch");
                        dec[share] = true;
                    });
                if (dec.length != K)
                {
                    logError("zfec decoded ", dec.length, " want ", K);
                    return 1;
                }
                return 0;
            }

            auto all = new ZfecShare[N];
            foreach (i; 0 .. N)
                all[i] = ZfecShare(i, got[i].ptr);
            if (auto e = decodeCheck(all))
                return e;

            auto subset = new ZfecShare[K];
            foreach (i; 0 .. K)
            {
                const size_t id = N - K + i;
                subset[i] = ZfecShare(id, got[id].ptr);
            }
            return decodeCheck(subset);
        });

    fails += checkMemutilsRepeat("zfec", {
        Unique!ZFEC z = new ZFEC(2, 4);
        ubyte[16] msg;
        foreach (i; 0 .. msg.length)
            msg[i] = cast(ubyte) i;
        z.encode(msg.ptr, msg.length, (size_t share, const(ubyte)* data, size_t len) {});
    });

    if (fails)
        logError("zfec failures: ", fails);
    assert(fails == 0);
}
