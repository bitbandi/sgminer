/*
* sm3 kernel implementation.
*
* ==========================(LICENSE BEGIN)============================
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* ===========================(LICENSE END)=============================
*
* @author   elbandi
*/

__constant static const sph_u32  SM3_IV[8] = {
	0x7380166F, 0x4914B2B9,
	0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA,
	0xE38DEE4D, 0xB0FB0E4E
};

#define SM3_P0(x) ((x) ^  SPH_ROTL32((x),9)  ^ SPH_ROTL32((x),17))
#define SM3_P1(x) ((x) ^  SPH_ROTL32((x),15) ^ SPH_ROTL32((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

#define SM3_COMPRESS(A,B,C,D,E,F,G,H)    do { \
		sph_u32 SS1,SS2,TT1,TT2,T[64]; \
		for(unsigned int j = 0; j < 16; j++) { \
			T[j] = 0x79CC4519; \
			SS1 = SPH_ROTL32((SPH_ROTL32(A,12) + E + SPH_ROTL32(T[j],j)), 7); \
			SS2 = SS1 ^ SPH_ROTL32(A,12); \
			TT1 = FF0(A,B,C) + D + SS2 + W1[j]; \
			TT2 = GG0(E,F,G) + H + SS1 + W[j]; \
			D = C; \
			C = SPH_ROTL32(B,9); \
			B = A; \
			A = TT1; \
			H = G; \
			G = SPH_ROTL32(F,19); \
			F = E; \
			E = SM3_P0(TT2); \
		} \
		for(unsigned int j = 16; j < 64; j++) { \
			T[j] = 0x7A879D8A; \
			SS1 = SPH_ROTL32((SPH_ROTL32(A,12) + E + SPH_ROTL32(T[j],j)), 7); \
			SS2 = SS1 ^ SPH_ROTL32(A,12); \
			TT1 = FF1(A,B,C) + D + SS2 + W1[j]; \
			TT2 = GG1(E,F,G) + H + SS1 + W[j]; \
			D = C; \
			C = SPH_ROTL32(B,9); \
			B = A; \
			A = TT1; \
			H = G; \
			G = SPH_ROTL32(F,19); \
			F = E; \
			E = SM3_P0(TT2); \
		} \
	} while (0)
