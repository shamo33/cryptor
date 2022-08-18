/**
 *  CryptK2 Library - KCipher-2(R) Implementation for C/C++
 *  Copyright (c) 2015-2022 Mystia.org Project. All rights reserved.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "cryptk2.h"
#include <stdlib.h>
#include <string.h>


#ifdef _MSC_VER
#define inline __forceinline
#endif


#if defined(_WIN32) && defined(CRYPTK2_MINIMAL)
#include <windows.h>
static HANDLE _heap;
static unsigned int _proc_attached = 0;
BOOL WINAPI DllMainCRTStartup(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		if (_proc_attached++ == 0) {
			// initialize
			if ((_heap = GetProcessHeap()) == NULL) {
				return FALSE;
			}
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		if (_proc_attached > 0) {
			if (--_proc_attached == 0) {
				// deinitialize
			}
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}
static inline void *my_malloc(size_t size) {
	return HeapAlloc(_heap, 0, size);
}
static inline void my_free(void *memory) {
	HeapFree(_heap, 0, memory);
}
#define malloc(a) my_malloc(a)
#define free(a) my_free(a)
#endif


// internal states of k2
struct _cryptk2 {
	uint32_t ik[12];     // Initial Key    (32 bits * 12 = 384 bits)
	uint32_t iv[8];      // Initial Vector (32 bits *  8 = 256 bits)
	uint32_t a[5];       // Feedback Shift Register A
	uint32_t b[11];      // Feedback Shift Register B
	uint32_t r1;         // Internal Register R1
	uint32_t r2;         // Internal Register R2
	uint32_t l1;         // Internal Register L1
	uint32_t l2;         // Internal Register L2
	uint32_t sh;         // Stream Register High
	uint32_t sl;         // Stream Register Low
	uint_fast8_t cnt;    // Counter
};

// lookup table for multiplicative operations: alpha_0[256]
static const uint32_t ta0[256] = {
	0x00000000u, 0xb6086d1au, 0xaf10da34u, 0x1918b72eu,
	0x9d207768u, 0x2b281a72u, 0x3230ad5cu, 0x8438c046u,
	0xf940eed0u, 0x4f4883cau, 0x565034e4u, 0xe05859feu,
	0x646099b8u, 0xd268f4a2u, 0xcb70438cu, 0x7d782e96u,
	0x31801f63u, 0x87887279u, 0x9e90c557u, 0x2898a84du,
	0xaca0680bu, 0x1aa80511u, 0x03b0b23fu, 0xb5b8df25u,
	0xc8c0f1b3u, 0x7ec89ca9u, 0x67d02b87u, 0xd1d8469du,
	0x55e086dbu, 0xe3e8ebc1u, 0xfaf05cefu, 0x4cf831f5u,
	0x62c33ec6u, 0xd4cb53dcu, 0xcdd3e4f2u, 0x7bdb89e8u,
	0xffe349aeu, 0x49eb24b4u, 0x50f3939au, 0xe6fbfe80u,
	0x9b83d016u, 0x2d8bbd0cu, 0x34930a22u, 0x829b6738u,
	0x06a3a77eu, 0xb0abca64u, 0xa9b37d4au, 0x1fbb1050u,
	0x534321a5u, 0xe54b4cbfu, 0xfc53fb91u, 0x4a5b968bu,
	0xce6356cdu, 0x786b3bd7u, 0x61738cf9u, 0xd77be1e3u,
	0xaa03cf75u, 0x1c0ba26fu, 0x05131541u, 0xb31b785bu,
	0x3723b81du, 0x812bd507u, 0x98336229u, 0x2e3b0f33u,
	0xc4457c4fu, 0x724d1155u, 0x6b55a67bu, 0xdd5dcb61u,
	0x59650b27u, 0xef6d663du, 0xf675d113u, 0x407dbc09u,
	0x3d05929fu, 0x8b0dff85u, 0x921548abu, 0x241d25b1u,
	0xa025e5f7u, 0x162d88edu, 0x0f353fc3u, 0xb93d52d9u,
	0xf5c5632cu, 0x43cd0e36u, 0x5ad5b918u, 0xecddd402u,
	0x68e51444u, 0xdeed795eu, 0xc7f5ce70u, 0x71fda36au,
	0x0c858dfcu, 0xba8de0e6u, 0xa39557c8u, 0x159d3ad2u,
	0x91a5fa94u, 0x27ad978eu, 0x3eb520a0u, 0x88bd4dbau,
	0xa6864289u, 0x108e2f93u, 0x099698bdu, 0xbf9ef5a7u,
	0x3ba635e1u, 0x8dae58fbu, 0x94b6efd5u, 0x22be82cfu,
	0x5fc6ac59u, 0xe9cec143u, 0xf0d6766du, 0x46de1b77u,
	0xc2e6db31u, 0x74eeb62bu, 0x6df60105u, 0xdbfe6c1fu,
	0x97065deau, 0x210e30f0u, 0x381687deu, 0x8e1eeac4u,
	0x0a262a82u, 0xbc2e4798u, 0xa536f0b6u, 0x133e9dacu,
	0x6e46b33au, 0xd84ede20u, 0xc156690eu, 0x775e0414u,
	0xf366c452u, 0x456ea948u, 0x5c761e66u, 0xea7e737cu,
	0x4b8af89eu, 0xfd829584u, 0xe49a22aau, 0x52924fb0u,
	0xd6aa8ff6u, 0x60a2e2ecu, 0x79ba55c2u, 0xcfb238d8u,
	0xb2ca164eu, 0x04c27b54u, 0x1ddacc7au, 0xabd2a160u,
	0x2fea6126u, 0x99e20c3cu, 0x80fabb12u, 0x36f2d608u,
	0x7a0ae7fdu, 0xcc028ae7u, 0xd51a3dc9u, 0x631250d3u,
	0xe72a9095u, 0x5122fd8fu, 0x483a4aa1u, 0xfe3227bbu,
	0x834a092du, 0x35426437u, 0x2c5ad319u, 0x9a52be03u,
	0x1e6a7e45u, 0xa862135fu, 0xb17aa471u, 0x0772c96bu,
	0x2949c658u, 0x9f41ab42u, 0x86591c6cu, 0x30517176u,
	0xb469b130u, 0x0261dc2au, 0x1b796b04u, 0xad71061eu,
	0xd0092888u, 0x66014592u, 0x7f19f2bcu, 0xc9119fa6u,
	0x4d295fe0u, 0xfb2132fau, 0xe23985d4u, 0x5431e8ceu,
	0x18c9d93bu, 0xaec1b421u, 0xb7d9030fu, 0x01d16e15u,
	0x85e9ae53u, 0x33e1c349u, 0x2af97467u, 0x9cf1197du,
	0xe18937ebu, 0x57815af1u, 0x4e99eddfu, 0xf89180c5u,
	0x7ca94083u, 0xcaa12d99u, 0xd3b99ab7u, 0x65b1f7adu,
	0x8fcf84d1u, 0x39c7e9cbu, 0x20df5ee5u, 0x96d733ffu,
	0x12eff3b9u, 0xa4e79ea3u, 0xbdff298du, 0x0bf74497u,
	0x768f6a01u, 0xc087071bu, 0xd99fb035u, 0x6f97dd2fu,
	0xebaf1d69u, 0x5da77073u, 0x44bfc75du, 0xf2b7aa47u,
	0xbe4f9bb2u, 0x0847f6a8u, 0x115f4186u, 0xa7572c9cu,
	0x236fecdau, 0x956781c0u, 0x8c7f36eeu, 0x3a775bf4u,
	0x470f7562u, 0xf1071878u, 0xe81faf56u, 0x5e17c24cu,
	0xda2f020au, 0x6c276f10u, 0x753fd83eu, 0xc337b524u,
	0xed0cba17u, 0x5b04d70du, 0x421c6023u, 0xf4140d39u,
	0x702ccd7fu, 0xc624a065u, 0xdf3c174bu, 0x69347a51u,
	0x144c54c7u, 0xa24439ddu, 0xbb5c8ef3u, 0x0d54e3e9u,
	0x896c23afu, 0x3f644eb5u, 0x267cf99bu, 0x90749481u,
	0xdc8ca574u, 0x6a84c86eu, 0x739c7f40u, 0xc594125au,
	0x41acd21cu, 0xf7a4bf06u, 0xeebc0828u, 0x58b46532u,
	0x25cc4ba4u, 0x93c426beu, 0x8adc9190u, 0x3cd4fc8au,
	0xb8ec3cccu, 0x0ee451d6u, 0x17fce6f8u, 0xa1f48be2u
};

// lookup table for multiplicative operations: alpha_1[256]
static const uint32_t ta1[256] = {
	0x00000000u, 0xa0f5fc2eu, 0x6dc7d55cu, 0xcd322972u,
	0xdaa387b8u, 0x7a567b96u, 0xb76452e4u, 0x1791aecau,
	0x996b235du, 0x399edf73u, 0xf4acf601u, 0x54590a2fu,
	0x43c8a4e5u, 0xe33d58cbu, 0x2e0f71b9u, 0x8efa8d97u,
	0x1fd646bau, 0xbf23ba94u, 0x721193e6u, 0xd2e46fc8u,
	0xc575c102u, 0x65803d2cu, 0xa8b2145eu, 0x0847e870u,
	0x86bd65e7u, 0x264899c9u, 0xeb7ab0bbu, 0x4b8f4c95u,
	0x5c1ee25fu, 0xfceb1e71u, 0x31d93703u, 0x912ccb2du,
	0x3e818c59u, 0x9e747077u, 0x53465905u, 0xf3b3a52bu,
	0xe4220be1u, 0x44d7f7cfu, 0x89e5debdu, 0x29102293u,
	0xa7eaaf04u, 0x071f532au, 0xca2d7a58u, 0x6ad88676u,
	0x7d4928bcu, 0xddbcd492u, 0x108efde0u, 0xb07b01ceu,
	0x2157cae3u, 0x81a236cdu, 0x4c901fbfu, 0xec65e391u,
	0xfbf44d5bu, 0x5b01b175u, 0x96339807u, 0x36c66429u,
	0xb83ce9beu, 0x18c91590u, 0xd5fb3ce2u, 0x750ec0ccu,
	0x629f6e06u, 0xc26a9228u, 0x0f58bb5au, 0xafad4774u,
	0x7c2f35b2u, 0xdcdac99cu, 0x11e8e0eeu, 0xb11d1cc0u,
	0xa68cb20au, 0x06794e24u, 0xcb4b6756u, 0x6bbe9b78u,
	0xe54416efu, 0x45b1eac1u, 0x8883c3b3u, 0x28763f9du,
	0x3fe79157u, 0x9f126d79u, 0x5220440bu, 0xf2d5b825u,
	0x63f97308u, 0xc30c8f26u, 0x0e3ea654u, 0xaecb5a7au,
	0xb95af4b0u, 0x19af089eu, 0xd49d21ecu, 0x7468ddc2u,
	0xfa925055u, 0x5a67ac7bu, 0x97558509u, 0x37a07927u,
	0x2031d7edu, 0x80c42bc3u, 0x4df602b1u, 0xed03fe9fu,
	0x42aeb9ebu, 0xe25b45c5u, 0x2f696cb7u, 0x8f9c9099u,
	0x980d3e53u, 0x38f8c27du, 0xf5caeb0fu, 0x553f1721u,
	0xdbc59ab6u, 0x7b306698u, 0xb6024feau, 0x16f7b3c4u,
	0x01661d0eu, 0xa193e120u, 0x6ca1c852u, 0xcc54347cu,
	0x5d78ff51u, 0xfd8d037fu, 0x30bf2a0du, 0x904ad623u,
	0x87db78e9u, 0x272e84c7u, 0xea1cadb5u, 0x4ae9519bu,
	0xc413dc0cu, 0x64e62022u, 0xa9d40950u, 0x0921f57eu,
	0x1eb05bb4u, 0xbe45a79au, 0x73778ee8u, 0xd38272c6u,
	0xf85e6a49u, 0x58ab9667u, 0x9599bf15u, 0x356c433bu,
	0x22fdedf1u, 0x820811dfu, 0x4f3a38adu, 0xefcfc483u,
	0x61354914u, 0xc1c0b53au, 0x0cf29c48u, 0xac076066u,
	0xbb96ceacu, 0x1b633282u, 0xd6511bf0u, 0x76a4e7deu,
	0xe7882cf3u, 0x477dd0ddu, 0x8a4ff9afu, 0x2aba0581u,
	0x3d2bab4bu, 0x9dde5765u, 0x50ec7e17u, 0xf0198239u,
	0x7ee30faeu, 0xde16f380u, 0x1324daf2u, 0xb3d126dcu,
	0xa4408816u, 0x04b57438u, 0xc9875d4au, 0x6972a164u,
	0xc6dfe610u, 0x662a1a3eu, 0xab18334cu, 0x0bedcf62u,
	0x1c7c61a8u, 0xbc899d86u, 0x71bbb4f4u, 0xd14e48dau,
	0x5fb4c54du, 0xff413963u, 0x32731011u, 0x9286ec3fu,
	0x851742f5u, 0x25e2bedbu, 0xe8d097a9u, 0x48256b87u,
	0xd909a0aau, 0x79fc5c84u, 0xb4ce75f6u, 0x143b89d8u,
	0x03aa2712u, 0xa35fdb3cu, 0x6e6df24eu, 0xce980e60u,
	0x406283f7u, 0xe0977fd9u, 0x2da556abu, 0x8d50aa85u,
	0x9ac1044fu, 0x3a34f861u, 0xf706d113u, 0x57f32d3du,
	0x84715ffbu, 0x2484a3d5u, 0xe9b68aa7u, 0x49437689u,
	0x5ed2d843u, 0xfe27246du, 0x33150d1fu, 0x93e0f131u,
	0x1d1a7ca6u, 0xbdef8088u, 0x70dda9fau, 0xd02855d4u,
	0xc7b9fb1eu, 0x674c0730u, 0xaa7e2e42u, 0x0a8bd26cu,
	0x9ba71941u, 0x3b52e56fu, 0xf660cc1du, 0x56953033u,
	0x41049ef9u, 0xe1f162d7u, 0x2cc34ba5u, 0x8c36b78bu,
	0x02cc3a1cu, 0xa239c632u, 0x6f0bef40u, 0xcffe136eu,
	0xd86fbda4u, 0x789a418au, 0xb5a868f8u, 0x155d94d6u,
	0xbaf0d3a2u, 0x1a052f8cu, 0xd73706feu, 0x77c2fad0u,
	0x6053541au, 0xc0a6a834u, 0x0d948146u, 0xad617d68u,
	0x239bf0ffu, 0x836e0cd1u, 0x4e5c25a3u, 0xeea9d98du,
	0xf9387747u, 0x59cd8b69u, 0x94ffa21bu, 0x340a5e35u,
	0xa5269518u, 0x05d36936u, 0xc8e14044u, 0x6814bc6au,
	0x7f8512a0u, 0xdf70ee8eu, 0x1242c7fcu, 0xb2b73bd2u,
	0x3c4db645u, 0x9cb84a6bu, 0x518a6319u, 0xf17f9f37u,
	0xe6ee31fdu, 0x461bcdd3u, 0x8b29e4a1u, 0x2bdc188fu
};

// lookup table for multiplicative operations: alpha_2[256]
static const uint32_t ta2[256] = {
	0x00000000u, 0x5bf87f93u, 0xb6bdfe6bu, 0xed4581f8u,
	0x2137b1d6u, 0x7acfce45u, 0x978a4fbdu, 0xcc72302eu,
	0x426e2fe1u, 0x19965072u, 0xf4d3d18au, 0xaf2bae19u,
	0x63599e37u, 0x38a1e1a4u, 0xd5e4605cu, 0x8e1c1fcfu,
	0x84dc5e8fu, 0xdf24211cu, 0x3261a0e4u, 0x6999df77u,
	0xa5ebef59u, 0xfe1390cau, 0x13561132u, 0x48ae6ea1u,
	0xc6b2716eu, 0x9d4a0efdu, 0x700f8f05u, 0x2bf7f096u,
	0xe785c0b8u, 0xbc7dbf2bu, 0x51383ed3u, 0x0ac04140u,
	0x45f5bc53u, 0x1e0dc3c0u, 0xf3484238u, 0xa8b03dabu,
	0x64c20d85u, 0x3f3a7216u, 0xd27ff3eeu, 0x89878c7du,
	0x079b93b2u, 0x5c63ec21u, 0xb1266dd9u, 0xeade124au,
	0x26ac2264u, 0x7d545df7u, 0x9011dc0fu, 0xcbe9a39cu,
	0xc129e2dcu, 0x9ad19d4fu, 0x77941cb7u, 0x2c6c6324u,
	0xe01e530au, 0xbbe62c99u, 0x56a3ad61u, 0x0d5bd2f2u,
	0x8347cd3du, 0xd8bfb2aeu, 0x35fa3356u, 0x6e024cc5u,
	0xa2707cebu, 0xf9880378u, 0x14cd8280u, 0x4f35fd13u,
	0x8aa735a6u, 0xd15f4a35u, 0x3c1acbcdu, 0x67e2b45eu,
	0xab908470u, 0xf068fbe3u, 0x1d2d7a1bu, 0x46d50588u,
	0xc8c91a47u, 0x933165d4u, 0x7e74e42cu, 0x258c9bbfu,
	0xe9feab91u, 0xb206d402u, 0x5f4355fau, 0x04bb2a69u,
	0x0e7b6b29u, 0x558314bau, 0xb8c69542u, 0xe33eead1u,
	0x2f4cdaffu, 0x74b4a56cu, 0x99f12494u, 0xc2095b07u,
	0x4c1544c8u, 0x17ed3b5bu, 0xfaa8baa3u, 0xa150c530u,
	0x6d22f51eu, 0x36da8a8du, 0xdb9f0b75u, 0x806774e6u,
	0xcf5289f5u, 0x94aaf666u, 0x79ef779eu, 0x2217080du,
	0xee653823u, 0xb59d47b0u, 0x58d8c648u, 0x0320b9dbu,
	0x8d3ca614u, 0xd6c4d987u, 0x3b81587fu, 0x607927ecu,
	0xac0b17c2u, 0xf7f36851u, 0x1ab6e9a9u, 0x414e963au,
	0x4b8ed77au, 0x1076a8e9u, 0xfd332911u, 0xa6cb5682u,
	0x6ab966acu, 0x3141193fu, 0xdc0498c7u, 0x87fce754u,
	0x09e0f89bu, 0x52188708u, 0xbf5d06f0u, 0xe4a57963u,
	0x28d7494du, 0x732f36deu, 0x9e6ab726u, 0xc592c8b5u,
	0x59036a01u, 0x02fb1592u, 0xefbe946au, 0xb446ebf9u,
	0x7834dbd7u, 0x23cca444u, 0xce8925bcu, 0x95715a2fu,
	0x1b6d45e0u, 0x40953a73u, 0xadd0bb8bu, 0xf628c418u,
	0x3a5af436u, 0x61a28ba5u, 0x8ce70a5du, 0xd71f75ceu,
	0xdddf348eu, 0x86274b1du, 0x6b62cae5u, 0x309ab576u,
	0xfce88558u, 0xa710facbu, 0x4a557b33u, 0x11ad04a0u,
	0x9fb11b6fu, 0xc44964fcu, 0x290ce504u, 0x72f49a97u,
	0xbe86aab9u, 0xe57ed52au, 0x083b54d2u, 0x53c32b41u,
	0x1cf6d652u, 0x470ea9c1u, 0xaa4b2839u, 0xf1b357aau,
	0x3dc16784u, 0x66391817u, 0x8b7c99efu, 0xd084e67cu,
	0x5e98f9b3u, 0x05608620u, 0xe82507d8u, 0xb3dd784bu,
	0x7faf4865u, 0x245737f6u, 0xc912b60eu, 0x92eac99du,
	0x982a88ddu, 0xc3d2f74eu, 0x2e9776b6u, 0x756f0925u,
	0xb91d390bu, 0xe2e54698u, 0x0fa0c760u, 0x5458b8f3u,
	0xda44a73cu, 0x81bcd8afu, 0x6cf95957u, 0x370126c4u,
	0xfb7316eau, 0xa08b6979u, 0x4dcee881u, 0x16369712u,
	0xd3a45fa7u, 0x885c2034u, 0x6519a1ccu, 0x3ee1de5fu,
	0xf293ee71u, 0xa96b91e2u, 0x442e101au, 0x1fd66f89u,
	0x91ca7046u, 0xca320fd5u, 0x27778e2du, 0x7c8ff1beu,
	0xb0fdc190u, 0xeb05be03u, 0x06403ffbu, 0x5db84068u,
	0x57780128u, 0x0c807ebbu, 0xe1c5ff43u, 0xba3d80d0u,
	0x764fb0feu, 0x2db7cf6du, 0xc0f24e95u, 0x9b0a3106u,
	0x15162ec9u, 0x4eee515au, 0xa3abd0a2u, 0xf853af31u,
	0x34219f1fu, 0x6fd9e08cu, 0x829c6174u, 0xd9641ee7u,
	0x9651e3f4u, 0xcda99c67u, 0x20ec1d9fu, 0x7b14620cu,
	0xb7665222u, 0xec9e2db1u, 0x01dbac49u, 0x5a23d3dau,
	0xd43fcc15u, 0x8fc7b386u, 0x6282327eu, 0x397a4dedu,
	0xf5087dc3u, 0xaef00250u, 0x43b583a8u, 0x184dfc3bu,
	0x128dbd7bu, 0x4975c2e8u, 0xa4304310u, 0xffc83c83u,
	0x33ba0cadu, 0x6842733eu, 0x8507f2c6u, 0xdeff8d55u,
	0x50e3929au, 0x0b1bed09u, 0xe65e6cf1u, 0xbda61362u,
	0x71d4234cu, 0x2a2c5cdfu, 0xc769dd27u, 0x9c91a2b4u
};

// lookup table for multiplicative operations: alpha_3[256]
static const uint32_t ta3[256] = {
	0x00000000u, 0x4559568bu, 0x8ab2ac73u, 0xcfebfaf8u,
	0x71013de6u, 0x34586b6du, 0xfbb39195u, 0xbeeac71eu,
	0xe2027aa9u, 0xa75b2c22u, 0x68b0d6dau, 0x2de98051u,
	0x9303474fu, 0xd65a11c4u, 0x19b1eb3cu, 0x5ce8bdb7u,
	0xa104f437u, 0xe45da2bcu, 0x2bb65844u, 0x6eef0ecfu,
	0xd005c9d1u, 0x955c9f5au, 0x5ab765a2u, 0x1fee3329u,
	0x43068e9eu, 0x065fd815u, 0xc9b422edu, 0x8ced7466u,
	0x3207b378u, 0x775ee5f3u, 0xb8b51f0bu, 0xfdec4980u,
	0x27088d6eu, 0x6251dbe5u, 0xadba211du, 0xe8e37796u,
	0x5609b088u, 0x1350e603u, 0xdcbb1cfbu, 0x99e24a70u,
	0xc50af7c7u, 0x8053a14cu, 0x4fb85bb4u, 0x0ae10d3fu,
	0xb40bca21u, 0xf1529caau, 0x3eb96652u, 0x7be030d9u,
	0x860c7959u, 0xc3552fd2u, 0x0cbed52au, 0x49e783a1u,
	0xf70d44bfu, 0xb2541234u, 0x7dbfe8ccu, 0x38e6be47u,
	0x640e03f0u, 0x2157557bu, 0xeebcaf83u, 0xabe5f908u,
	0x150f3e16u, 0x5056689du, 0x9fbd9265u, 0xdae4c4eeu,
	0x4e107fdcu, 0x0b492957u, 0xc4a2d3afu, 0x81fb8524u,
	0x3f11423au, 0x7a4814b1u, 0xb5a3ee49u, 0xf0fab8c2u,
	0xac120575u, 0xe94b53feu, 0x26a0a906u, 0x63f9ff8du,
	0xdd133893u, 0x984a6e18u, 0x57a194e0u, 0x12f8c26bu,
	0xef148bebu, 0xaa4ddd60u, 0x65a62798u, 0x20ff7113u,
	0x9e15b60du, 0xdb4ce086u, 0x14a71a7eu, 0x51fe4cf5u,
	0x0d16f142u, 0x484fa7c9u, 0x87a45d31u, 0xc2fd0bbau,
	0x7c17cca4u, 0x394e9a2fu, 0xf6a560d7u, 0xb3fc365cu,
	0x6918f2b2u, 0x2c41a439u, 0xe3aa5ec1u, 0xa6f3084au,
	0x1819cf54u, 0x5d4099dfu, 0x92ab6327u, 0xd7f235acu,
	0x8b1a881bu, 0xce43de90u, 0x01a82468u, 0x44f172e3u,
	0xfa1bb5fdu, 0xbf42e376u, 0x70a9198eu, 0x35f04f05u,
	0xc81c0685u, 0x8d45500eu, 0x42aeaaf6u, 0x07f7fc7du,
	0xb91d3b63u, 0xfc446de8u, 0x33af9710u, 0x76f6c19bu,
	0x2a1e7c2cu, 0x6f472aa7u, 0xa0acd05fu, 0xe5f586d4u,
	0x5b1f41cau, 0x1e461741u, 0xd1adedb9u, 0x94f4bb32u,
	0x9c20feddu, 0xd979a856u, 0x169252aeu, 0x53cb0425u,
	0xed21c33bu, 0xa87895b0u, 0x67936f48u, 0x22ca39c3u,
	0x7e228474u, 0x3b7bd2ffu, 0xf4902807u, 0xb1c97e8cu,
	0x0f23b992u, 0x4a7aef19u, 0x859115e1u, 0xc0c8436au,
	0x3d240aeau, 0x787d5c61u, 0xb796a699u, 0xf2cff012u,
	0x4c25370cu, 0x097c6187u, 0xc6979b7fu, 0x83cecdf4u,
	0xdf267043u, 0x9a7f26c8u, 0x5594dc30u, 0x10cd8abbu,
	0xae274da5u, 0xeb7e1b2eu, 0x2495e1d6u, 0x61ccb75du,
	0xbb2873b3u, 0xfe712538u, 0x319adfc0u, 0x74c3894bu,
	0xca294e55u, 0x8f7018deu, 0x409be226u, 0x05c2b4adu,
	0x592a091au, 0x1c735f91u, 0xd398a569u, 0x96c1f3e2u,
	0x282b34fcu, 0x6d726277u, 0xa299988fu, 0xe7c0ce04u,
	0x1a2c8784u, 0x5f75d10fu, 0x909e2bf7u, 0xd5c77d7cu,
	0x6b2dba62u, 0x2e74ece9u, 0xe19f1611u, 0xa4c6409au,
	0xf82efd2du, 0xbd77aba6u, 0x729c515eu, 0x37c507d5u,
	0x892fc0cbu, 0xcc769640u, 0x039d6cb8u, 0x46c43a33u,
	0xd2308101u, 0x9769d78au, 0x58822d72u, 0x1ddb7bf9u,
	0xa331bce7u, 0xe668ea6cu, 0x29831094u, 0x6cda461fu,
	0x3032fba8u, 0x756bad23u, 0xba8057dbu, 0xffd90150u,
	0x4133c64eu, 0x046a90c5u, 0xcb816a3du, 0x8ed83cb6u,
	0x73347536u, 0x366d23bdu, 0xf986d945u, 0xbcdf8fceu,
	0x023548d0u, 0x476c1e5bu, 0x8887e4a3u, 0xcddeb228u,
	0x91360f9fu, 0xd46f5914u, 0x1b84a3ecu, 0x5eddf567u,
	0xe0373279u, 0xa56e64f2u, 0x6a859e0au, 0x2fdcc881u,
	0xf5380c6fu, 0xb0615ae4u, 0x7f8aa01cu, 0x3ad3f697u,
	0x84393189u, 0xc1606702u, 0x0e8b9dfau, 0x4bd2cb71u,
	0x173a76c6u, 0x5263204du, 0x9d88dab5u, 0xd8d18c3eu,
	0x663b4b20u, 0x23621dabu, 0xec89e753u, 0xa9d0b1d8u,
	0x543cf858u, 0x1165aed3u, 0xde8e542bu, 0x9bd702a0u,
	0x253dc5beu, 0x60649335u, 0xaf8f69cdu, 0xead63f46u,
	0xb63e82f1u, 0xf367d47au, 0x3c8c2e82u, 0x79d57809u,
	0xc73fbf17u, 0x8266e99cu, 0x4d8d1364u, 0x08d445efu
};


// lookup table for sub in the nonlinear function part: T_0[256]
static const uint32_t ts0[256] = {
	0xa56363c6u, 0x847c7cf8u, 0x997777eeu, 0x8d7b7bf6u,
	0x0df2f2ffu, 0xbd6b6bd6u, 0xb16f6fdeu, 0x54c5c591u,
	0x50303060u, 0x03010102u, 0xa96767ceu, 0x7d2b2b56u,
	0x19fefee7u, 0x62d7d7b5u, 0xe6abab4du, 0x9a7676ecu,
	0x45caca8fu, 0x9d82821fu, 0x40c9c989u, 0x877d7dfau,
	0x15fafaefu, 0xeb5959b2u, 0xc947478eu, 0x0bf0f0fbu,
	0xecadad41u, 0x67d4d4b3u, 0xfda2a25fu, 0xeaafaf45u,
	0xbf9c9c23u, 0xf7a4a453u, 0x967272e4u, 0x5bc0c09bu,
	0xc2b7b775u, 0x1cfdfde1u, 0xae93933du, 0x6a26264cu,
	0x5a36366cu, 0x413f3f7eu, 0x02f7f7f5u, 0x4fcccc83u,
	0x5c343468u, 0xf4a5a551u, 0x34e5e5d1u, 0x08f1f1f9u,
	0x937171e2u, 0x73d8d8abu, 0x53313162u, 0x3f15152au,
	0x0c040408u, 0x52c7c795u, 0x65232346u, 0x5ec3c39du,
	0x28181830u, 0xa1969637u, 0x0f05050au, 0xb59a9a2fu,
	0x0907070eu, 0x36121224u, 0x9b80801bu, 0x3de2e2dfu,
	0x26ebebcdu, 0x6927274eu, 0xcdb2b27fu, 0x9f7575eau,
	0x1b090912u, 0x9e83831du, 0x742c2c58u, 0x2e1a1a34u,
	0x2d1b1b36u, 0xb26e6edcu, 0xee5a5ab4u, 0xfba0a05bu,
	0xf65252a4u, 0x4d3b3b76u, 0x61d6d6b7u, 0xceb3b37du,
	0x7b292952u, 0x3ee3e3ddu, 0x712f2f5eu, 0x97848413u,
	0xf55353a6u, 0x68d1d1b9u, 0x00000000u, 0x2cededc1u,
	0x60202040u, 0x1ffcfce3u, 0xc8b1b179u, 0xed5b5bb6u,
	0xbe6a6ad4u, 0x46cbcb8du, 0xd9bebe67u, 0x4b393972u,
	0xde4a4a94u, 0xd44c4c98u, 0xe85858b0u, 0x4acfcf85u,
	0x6bd0d0bbu, 0x2aefefc5u, 0xe5aaaa4fu, 0x16fbfbedu,
	0xc5434386u, 0xd74d4d9au, 0x55333366u, 0x94858511u,
	0xcf45458au, 0x10f9f9e9u, 0x06020204u, 0x817f7ffeu,
	0xf05050a0u, 0x443c3c78u, 0xba9f9f25u, 0xe3a8a84bu,
	0xf35151a2u, 0xfea3a35du, 0xc0404080u, 0x8a8f8f05u,
	0xad92923fu, 0xbc9d9d21u, 0x48383870u, 0x04f5f5f1u,
	0xdfbcbc63u, 0xc1b6b677u, 0x75dadaafu, 0x63212142u,
	0x30101020u, 0x1affffe5u, 0x0ef3f3fdu, 0x6dd2d2bfu,
	0x4ccdcd81u, 0x140c0c18u, 0x35131326u, 0x2fececc3u,
	0xe15f5fbeu, 0xa2979735u, 0xcc444488u, 0x3917172eu,
	0x57c4c493u, 0xf2a7a755u, 0x827e7efcu, 0x473d3d7au,
	0xac6464c8u, 0xe75d5dbau, 0x2b191932u, 0x957373e6u,
	0xa06060c0u, 0x98818119u, 0xd14f4f9eu, 0x7fdcdca3u,
	0x66222244u, 0x7e2a2a54u, 0xab90903bu, 0x8388880bu,
	0xca46468cu, 0x29eeeec7u, 0xd3b8b86bu, 0x3c141428u,
	0x79dedea7u, 0xe25e5ebcu, 0x1d0b0b16u, 0x76dbdbadu,
	0x3be0e0dbu, 0x56323264u, 0x4e3a3a74u, 0x1e0a0a14u,
	0xdb494992u, 0x0a06060cu, 0x6c242448u, 0xe45c5cb8u,
	0x5dc2c29fu, 0x6ed3d3bdu, 0xefacac43u, 0xa66262c4u,
	0xa8919139u, 0xa4959531u, 0x37e4e4d3u, 0x8b7979f2u,
	0x32e7e7d5u, 0x43c8c88bu, 0x5937376eu, 0xb76d6ddau,
	0x8c8d8d01u, 0x64d5d5b1u, 0xd24e4e9cu, 0xe0a9a949u,
	0xb46c6cd8u, 0xfa5656acu, 0x07f4f4f3u, 0x25eaeacfu,
	0xaf6565cau, 0x8e7a7af4u, 0xe9aeae47u, 0x18080810u,
	0xd5baba6fu, 0x887878f0u, 0x6f25254au, 0x722e2e5cu,
	0x241c1c38u, 0xf1a6a657u, 0xc7b4b473u, 0x51c6c697u,
	0x23e8e8cbu, 0x7cdddda1u, 0x9c7474e8u, 0x211f1f3eu,
	0xdd4b4b96u, 0xdcbdbd61u, 0x868b8b0du, 0x858a8a0fu,
	0x907070e0u, 0x423e3e7cu, 0xc4b5b571u, 0xaa6666ccu,
	0xd8484890u, 0x05030306u, 0x01f6f6f7u, 0x120e0e1cu,
	0xa36161c2u, 0x5f35356au, 0xf95757aeu, 0xd0b9b969u,
	0x91868617u, 0x58c1c199u, 0x271d1d3au, 0xb99e9e27u,
	0x38e1e1d9u, 0x13f8f8ebu, 0xb398982bu, 0x33111122u,
	0xbb6969d2u, 0x70d9d9a9u, 0x898e8e07u, 0xa7949433u,
	0xb69b9b2du, 0x221e1e3cu, 0x92878715u, 0x20e9e9c9u,
	0x49cece87u, 0xff5555aau, 0x78282850u, 0x7adfdfa5u,
	0x8f8c8c03u, 0xf8a1a159u, 0x80898909u, 0x170d0d1au,
	0xdabfbf65u, 0x31e6e6d7u, 0xc6424284u, 0xb86868d0u,
	0xc3414182u, 0xb0999929u, 0x772d2d5au, 0x110f0f1eu,
	0xcbb0b07bu, 0xfc5454a8u, 0xd6bbbb6du, 0x3a16162cu
};

// lookup table for sub in the nonlinear function part: T_1[256]
static const uint32_t ts1[256] = {
	0x6363c6a5u, 0x7c7cf884u, 0x7777ee99u, 0x7b7bf68du,
	0xf2f2ff0du, 0x6b6bd6bdu, 0x6f6fdeb1u, 0xc5c59154u,
	0x30306050u, 0x01010203u, 0x6767cea9u, 0x2b2b567du,
	0xfefee719u, 0xd7d7b562u, 0xabab4de6u, 0x7676ec9au,
	0xcaca8f45u, 0x82821f9du, 0xc9c98940u, 0x7d7dfa87u,
	0xfafaef15u, 0x5959b2ebu, 0x47478ec9u, 0xf0f0fb0bu,
	0xadad41ecu, 0xd4d4b367u, 0xa2a25ffdu, 0xafaf45eau,
	0x9c9c23bfu, 0xa4a453f7u, 0x7272e496u, 0xc0c09b5bu,
	0xb7b775c2u, 0xfdfde11cu, 0x93933daeu, 0x26264c6au,
	0x36366c5au, 0x3f3f7e41u, 0xf7f7f502u, 0xcccc834fu,
	0x3434685cu, 0xa5a551f4u, 0xe5e5d134u, 0xf1f1f908u,
	0x7171e293u, 0xd8d8ab73u, 0x31316253u, 0x15152a3fu,
	0x0404080cu, 0xc7c79552u, 0x23234665u, 0xc3c39d5eu,
	0x18183028u, 0x969637a1u, 0x05050a0fu, 0x9a9a2fb5u,
	0x07070e09u, 0x12122436u, 0x80801b9bu, 0xe2e2df3du,
	0xebebcd26u, 0x27274e69u, 0xb2b27fcdu, 0x7575ea9fu,
	0x0909121bu, 0x83831d9eu, 0x2c2c5874u, 0x1a1a342eu,
	0x1b1b362du, 0x6e6edcb2u, 0x5a5ab4eeu, 0xa0a05bfbu,
	0x5252a4f6u, 0x3b3b764du, 0xd6d6b761u, 0xb3b37dceu,
	0x2929527bu, 0xe3e3dd3eu, 0x2f2f5e71u, 0x84841397u,
	0x5353a6f5u, 0xd1d1b968u, 0x00000000u, 0xededc12cu,
	0x20204060u, 0xfcfce31fu, 0xb1b179c8u, 0x5b5bb6edu,
	0x6a6ad4beu, 0xcbcb8d46u, 0xbebe67d9u, 0x3939724bu,
	0x4a4a94deu, 0x4c4c98d4u, 0x5858b0e8u, 0xcfcf854au,
	0xd0d0bb6bu, 0xefefc52au, 0xaaaa4fe5u, 0xfbfbed16u,
	0x434386c5u, 0x4d4d9ad7u, 0x33336655u, 0x85851194u,
	0x45458acfu, 0xf9f9e910u, 0x02020406u, 0x7f7ffe81u,
	0x5050a0f0u, 0x3c3c7844u, 0x9f9f25bau, 0xa8a84be3u,
	0x5151a2f3u, 0xa3a35dfeu, 0x404080c0u, 0x8f8f058au,
	0x92923fadu, 0x9d9d21bcu, 0x38387048u, 0xf5f5f104u,
	0xbcbc63dfu, 0xb6b677c1u, 0xdadaaf75u, 0x21214263u,
	0x10102030u, 0xffffe51au, 0xf3f3fd0eu, 0xd2d2bf6du,
	0xcdcd814cu, 0x0c0c1814u, 0x13132635u, 0xececc32fu,
	0x5f5fbee1u, 0x979735a2u, 0x444488ccu, 0x17172e39u,
	0xc4c49357u, 0xa7a755f2u, 0x7e7efc82u, 0x3d3d7a47u,
	0x6464c8acu, 0x5d5dbae7u, 0x1919322bu, 0x7373e695u,
	0x6060c0a0u, 0x81811998u, 0x4f4f9ed1u, 0xdcdca37fu,
	0x22224466u, 0x2a2a547eu, 0x90903babu, 0x88880b83u,
	0x46468ccau, 0xeeeec729u, 0xb8b86bd3u, 0x1414283cu,
	0xdedea779u, 0x5e5ebce2u, 0x0b0b161du, 0xdbdbad76u,
	0xe0e0db3bu, 0x32326456u, 0x3a3a744eu, 0x0a0a141eu,
	0x494992dbu, 0x06060c0au, 0x2424486cu, 0x5c5cb8e4u,
	0xc2c29f5du, 0xd3d3bd6eu, 0xacac43efu, 0x6262c4a6u,
	0x919139a8u, 0x959531a4u, 0xe4e4d337u, 0x7979f28bu,
	0xe7e7d532u, 0xc8c88b43u, 0x37376e59u, 0x6d6ddab7u,
	0x8d8d018cu, 0xd5d5b164u, 0x4e4e9cd2u, 0xa9a949e0u,
	0x6c6cd8b4u, 0x5656acfau, 0xf4f4f307u, 0xeaeacf25u,
	0x6565caafu, 0x7a7af48eu, 0xaeae47e9u, 0x08081018u,
	0xbaba6fd5u, 0x7878f088u, 0x25254a6fu, 0x2e2e5c72u,
	0x1c1c3824u, 0xa6a657f1u, 0xb4b473c7u, 0xc6c69751u,
	0xe8e8cb23u, 0xdddda17cu, 0x7474e89cu, 0x1f1f3e21u,
	0x4b4b96ddu, 0xbdbd61dcu, 0x8b8b0d86u, 0x8a8a0f85u,
	0x7070e090u, 0x3e3e7c42u, 0xb5b571c4u, 0x6666ccaau,
	0x484890d8u, 0x03030605u, 0xf6f6f701u, 0x0e0e1c12u,
	0x6161c2a3u, 0x35356a5fu, 0x5757aef9u, 0xb9b969d0u,
	0x86861791u, 0xc1c19958u, 0x1d1d3a27u, 0x9e9e27b9u,
	0xe1e1d938u, 0xf8f8eb13u, 0x98982bb3u, 0x11112233u,
	0x6969d2bbu, 0xd9d9a970u, 0x8e8e0789u, 0x949433a7u,
	0x9b9b2db6u, 0x1e1e3c22u, 0x87871592u, 0xe9e9c920u,
	0xcece8749u, 0x5555aaffu, 0x28285078u, 0xdfdfa57au,
	0x8c8c038fu, 0xa1a159f8u, 0x89890980u, 0x0d0d1a17u,
	0xbfbf65dau, 0xe6e6d731u, 0x424284c6u, 0x6868d0b8u,
	0x414182c3u, 0x999929b0u, 0x2d2d5a77u, 0x0f0f1e11u,
	0xb0b07bcbu, 0x5454a8fcu, 0xbbbb6dd6u, 0x16162c3au
};

// lookup table for sub in the nonlinear function part: T_2[256]
static const uint32_t ts2[256] = {
	0x63c6a563u, 0x7cf8847cu, 0x77ee9977u, 0x7bf68d7bu,
	0xf2ff0df2u, 0x6bd6bd6bu, 0x6fdeb16fu, 0xc59154c5u,
	0x30605030u, 0x01020301u, 0x67cea967u, 0x2b567d2bu,
	0xfee719feu, 0xd7b562d7u, 0xab4de6abu, 0x76ec9a76u,
	0xca8f45cau, 0x821f9d82u, 0xc98940c9u, 0x7dfa877du,
	0xfaef15fau, 0x59b2eb59u, 0x478ec947u, 0xf0fb0bf0u,
	0xad41ecadu, 0xd4b367d4u, 0xa25ffda2u, 0xaf45eaafu,
	0x9c23bf9cu, 0xa453f7a4u, 0x72e49672u, 0xc09b5bc0u,
	0xb775c2b7u, 0xfde11cfdu, 0x933dae93u, 0x264c6a26u,
	0x366c5a36u, 0x3f7e413fu, 0xf7f502f7u, 0xcc834fccu,
	0x34685c34u, 0xa551f4a5u, 0xe5d134e5u, 0xf1f908f1u,
	0x71e29371u, 0xd8ab73d8u, 0x31625331u, 0x152a3f15u,
	0x04080c04u, 0xc79552c7u, 0x23466523u, 0xc39d5ec3u,
	0x18302818u, 0x9637a196u, 0x050a0f05u, 0x9a2fb59au,
	0x070e0907u, 0x12243612u, 0x801b9b80u, 0xe2df3de2u,
	0xebcd26ebu, 0x274e6927u, 0xb27fcdb2u, 0x75ea9f75u,
	0x09121b09u, 0x831d9e83u, 0x2c58742cu, 0x1a342e1au,
	0x1b362d1bu, 0x6edcb26eu, 0x5ab4ee5au, 0xa05bfba0u,
	0x52a4f652u, 0x3b764d3bu, 0xd6b761d6u, 0xb37dceb3u,
	0x29527b29u, 0xe3dd3ee3u, 0x2f5e712fu, 0x84139784u,
	0x53a6f553u, 0xd1b968d1u, 0x00000000u, 0xedc12cedu,
	0x20406020u, 0xfce31ffcu, 0xb179c8b1u, 0x5bb6ed5bu,
	0x6ad4be6au, 0xcb8d46cbu, 0xbe67d9beu, 0x39724b39u,
	0x4a94de4au, 0x4c98d44cu, 0x58b0e858u, 0xcf854acfu,
	0xd0bb6bd0u, 0xefc52aefu, 0xaa4fe5aau, 0xfbed16fbu,
	0x4386c543u, 0x4d9ad74du, 0x33665533u, 0x85119485u,
	0x458acf45u, 0xf9e910f9u, 0x02040602u, 0x7ffe817fu,
	0x50a0f050u, 0x3c78443cu, 0x9f25ba9fu, 0xa84be3a8u,
	0x51a2f351u, 0xa35dfea3u, 0x4080c040u, 0x8f058a8fu,
	0x923fad92u, 0x9d21bc9du, 0x38704838u, 0xf5f104f5u,
	0xbc63dfbcu, 0xb677c1b6u, 0xdaaf75dau, 0x21426321u,
	0x10203010u, 0xffe51affu, 0xf3fd0ef3u, 0xd2bf6dd2u,
	0xcd814ccdu, 0x0c18140cu, 0x13263513u, 0xecc32fecu,
	0x5fbee15fu, 0x9735a297u, 0x4488cc44u, 0x172e3917u,
	0xc49357c4u, 0xa755f2a7u, 0x7efc827eu, 0x3d7a473du,
	0x64c8ac64u, 0x5dbae75du, 0x19322b19u, 0x73e69573u,
	0x60c0a060u, 0x81199881u, 0x4f9ed14fu, 0xdca37fdcu,
	0x22446622u, 0x2a547e2au, 0x903bab90u, 0x880b8388u,
	0x468cca46u, 0xeec729eeu, 0xb86bd3b8u, 0x14283c14u,
	0xdea779deu, 0x5ebce25eu, 0x0b161d0bu, 0xdbad76dbu,
	0xe0db3be0u, 0x32645632u, 0x3a744e3au, 0x0a141e0au,
	0x4992db49u, 0x060c0a06u, 0x24486c24u, 0x5cb8e45cu,
	0xc29f5dc2u, 0xd3bd6ed3u, 0xac43efacu, 0x62c4a662u,
	0x9139a891u, 0x9531a495u, 0xe4d337e4u, 0x79f28b79u,
	0xe7d532e7u, 0xc88b43c8u, 0x376e5937u, 0x6ddab76du,
	0x8d018c8du, 0xd5b164d5u, 0x4e9cd24eu, 0xa949e0a9u,
	0x6cd8b46cu, 0x56acfa56u, 0xf4f307f4u, 0xeacf25eau,
	0x65caaf65u, 0x7af48e7au, 0xae47e9aeu, 0x08101808u,
	0xba6fd5bau, 0x78f08878u, 0x254a6f25u, 0x2e5c722eu,
	0x1c38241cu, 0xa657f1a6u, 0xb473c7b4u, 0xc69751c6u,
	0xe8cb23e8u, 0xdda17cddu, 0x74e89c74u, 0x1f3e211fu,
	0x4b96dd4bu, 0xbd61dcbdu, 0x8b0d868bu, 0x8a0f858au,
	0x70e09070u, 0x3e7c423eu, 0xb571c4b5u, 0x66ccaa66u,
	0x4890d848u, 0x03060503u, 0xf6f701f6u, 0x0e1c120eu,
	0x61c2a361u, 0x356a5f35u, 0x57aef957u, 0xb969d0b9u,
	0x86179186u, 0xc19958c1u, 0x1d3a271du, 0x9e27b99eu,
	0xe1d938e1u, 0xf8eb13f8u, 0x982bb398u, 0x11223311u,
	0x69d2bb69u, 0xd9a970d9u, 0x8e07898eu, 0x9433a794u,
	0x9b2db69bu, 0x1e3c221eu, 0x87159287u, 0xe9c920e9u,
	0xce8749ceu, 0x55aaff55u, 0x28507828u, 0xdfa57adfu,
	0x8c038f8cu, 0xa159f8a1u, 0x89098089u, 0x0d1a170du,
	0xbf65dabfu, 0xe6d731e6u, 0x4284c642u, 0x68d0b868u,
	0x4182c341u, 0x9929b099u, 0x2d5a772du, 0x0f1e110fu,
	0xb07bcbb0u, 0x54a8fc54u, 0xbb6dd6bbu, 0x162c3a16u
};

// lookup table for sub in the nonlinear function part: T_3[256]
static const uint32_t ts3[256] = {
	0xc6a56363u, 0xf8847c7cu, 0xee997777u, 0xf68d7b7bu,
	0xff0df2f2u, 0xd6bd6b6bu, 0xdeb16f6fu, 0x9154c5c5u,
	0x60503030u, 0x02030101u, 0xcea96767u, 0x567d2b2bu,
	0xe719fefeu, 0xb562d7d7u, 0x4de6ababu, 0xec9a7676u,
	0x8f45cacau, 0x1f9d8282u, 0x8940c9c9u, 0xfa877d7du,
	0xef15fafau, 0xb2eb5959u, 0x8ec94747u, 0xfb0bf0f0u,
	0x41ecadadu, 0xb367d4d4u, 0x5ffda2a2u, 0x45eaafafu,
	0x23bf9c9cu, 0x53f7a4a4u, 0xe4967272u, 0x9b5bc0c0u,
	0x75c2b7b7u, 0xe11cfdfdu, 0x3dae9393u, 0x4c6a2626u,
	0x6c5a3636u, 0x7e413f3fu, 0xf502f7f7u, 0x834fccccu,
	0x685c3434u, 0x51f4a5a5u, 0xd134e5e5u, 0xf908f1f1u,
	0xe2937171u, 0xab73d8d8u, 0x62533131u, 0x2a3f1515u,
	0x080c0404u, 0x9552c7c7u, 0x46652323u, 0x9d5ec3c3u,
	0x30281818u, 0x37a19696u, 0x0a0f0505u, 0x2fb59a9au,
	0x0e090707u, 0x24361212u, 0x1b9b8080u, 0xdf3de2e2u,
	0xcd26ebebu, 0x4e692727u, 0x7fcdb2b2u, 0xea9f7575u,
	0x121b0909u, 0x1d9e8383u, 0x58742c2cu, 0x342e1a1au,
	0x362d1b1bu, 0xdcb26e6eu, 0xb4ee5a5au, 0x5bfba0a0u,
	0xa4f65252u, 0x764d3b3bu, 0xb761d6d6u, 0x7dceb3b3u,
	0x527b2929u, 0xdd3ee3e3u, 0x5e712f2fu, 0x13978484u,
	0xa6f55353u, 0xb968d1d1u, 0x00000000u, 0xc12cededu,
	0x40602020u, 0xe31ffcfcu, 0x79c8b1b1u, 0xb6ed5b5bu,
	0xd4be6a6au, 0x8d46cbcbu, 0x67d9bebeu, 0x724b3939u,
	0x94de4a4au, 0x98d44c4cu, 0xb0e85858u, 0x854acfcfu,
	0xbb6bd0d0u, 0xc52aefefu, 0x4fe5aaaau, 0xed16fbfbu,
	0x86c54343u, 0x9ad74d4du, 0x66553333u, 0x11948585u,
	0x8acf4545u, 0xe910f9f9u, 0x04060202u, 0xfe817f7fu,
	0xa0f05050u, 0x78443c3cu, 0x25ba9f9fu, 0x4be3a8a8u,
	0xa2f35151u, 0x5dfea3a3u, 0x80c04040u, 0x058a8f8fu,
	0x3fad9292u, 0x21bc9d9du, 0x70483838u, 0xf104f5f5u,
	0x63dfbcbcu, 0x77c1b6b6u, 0xaf75dadau, 0x42632121u,
	0x20301010u, 0xe51affffu, 0xfd0ef3f3u, 0xbf6dd2d2u,
	0x814ccdcdu, 0x18140c0cu, 0x26351313u, 0xc32fececu,
	0xbee15f5fu, 0x35a29797u, 0x88cc4444u, 0x2e391717u,
	0x9357c4c4u, 0x55f2a7a7u, 0xfc827e7eu, 0x7a473d3du,
	0xc8ac6464u, 0xbae75d5du, 0x322b1919u, 0xe6957373u,
	0xc0a06060u, 0x19988181u, 0x9ed14f4fu, 0xa37fdcdcu,
	0x44662222u, 0x547e2a2au, 0x3bab9090u, 0x0b838888u,
	0x8cca4646u, 0xc729eeeeu, 0x6bd3b8b8u, 0x283c1414u,
	0xa779dedeu, 0xbce25e5eu, 0x161d0b0bu, 0xad76dbdbu,
	0xdb3be0e0u, 0x64563232u, 0x744e3a3au, 0x141e0a0au,
	0x92db4949u, 0x0c0a0606u, 0x486c2424u, 0xb8e45c5cu,
	0x9f5dc2c2u, 0xbd6ed3d3u, 0x43efacacu, 0xc4a66262u,
	0x39a89191u, 0x31a49595u, 0xd337e4e4u, 0xf28b7979u,
	0xd532e7e7u, 0x8b43c8c8u, 0x6e593737u, 0xdab76d6du,
	0x018c8d8du, 0xb164d5d5u, 0x9cd24e4eu, 0x49e0a9a9u,
	0xd8b46c6cu, 0xacfa5656u, 0xf307f4f4u, 0xcf25eaeau,
	0xcaaf6565u, 0xf48e7a7au, 0x47e9aeaeu, 0x10180808u,
	0x6fd5babau, 0xf0887878u, 0x4a6f2525u, 0x5c722e2eu,
	0x38241c1cu, 0x57f1a6a6u, 0x73c7b4b4u, 0x9751c6c6u,
	0xcb23e8e8u, 0xa17cddddu, 0xe89c7474u, 0x3e211f1fu,
	0x96dd4b4bu, 0x61dcbdbdu, 0x0d868b8bu, 0x0f858a8au,
	0xe0907070u, 0x7c423e3eu, 0x71c4b5b5u, 0xccaa6666u,
	0x90d84848u, 0x06050303u, 0xf701f6f6u, 0x1c120e0eu,
	0xc2a36161u, 0x6a5f3535u, 0xaef95757u, 0x69d0b9b9u,
	0x17918686u, 0x9958c1c1u, 0x3a271d1du, 0x27b99e9eu,
	0xd938e1e1u, 0xeb13f8f8u, 0x2bb39898u, 0x22331111u,
	0xd2bb6969u, 0xa970d9d9u, 0x07898e8eu, 0x33a79494u,
	0x2db69b9bu, 0x3c221e1eu, 0x15928787u, 0xc920e9e9u,
	0x8749ceceu, 0xaaff5555u, 0x50782828u, 0xa57adfdfu,
	0x038f8c8cu, 0x59f8a1a1u, 0x09808989u, 0x1a170d0du,
	0x65dabfbfu, 0xd731e6e6u, 0x84c64242u, 0xd0b86868u,
	0x82c34141u, 0x29b09999u, 0x5a772d2du, 0x1e110f0fu,
	0x7bcbb0b0u, 0xa8fc5454u, 0x6dd6bbbbu, 0x2c3a1616u
};

// private types
enum mode_crypt { MODE_CRYPT, MODE_STREAM };
enum mode_update { MODE_SETUP, MODE_UPDATE };

// private functions
static inline void update_internal(CRYPTK2 state, const enum mode_update mode);
static inline void setup_internal(CRYPTK2 state);
static inline void update(CRYPTK2 state);
static inline void crypt_internal(CRYPTK2 state, const enum mode_crypt mode, size_t len, const uint8_t *in, uint8_t *out);
static inline uint32_t pack_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
static inline uint8_t unpack_uint32_first(uint32_t u);
static inline uint8_t unpack_uint32_second(uint32_t u);
static inline uint8_t unpack_uint32_third(uint32_t u);
static inline uint8_t unpack_uint32_last(uint32_t u);
static inline uint32_t mul_a0(uint32_t u);
static inline uint32_t mul_a1(uint32_t u);
static inline uint32_t mul_a2(uint32_t u);
static inline uint32_t mul_a3(uint32_t u);
static inline uint32_t sub(uint32_t u);
static inline uint32_t nlf(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
static inline void gen_stream(CRYPTK2 state);


// initialize internal state of k2
CRYPTK2 CRYPTK2_API new_cryptk2(void) {
	CRYPTK2 state;

	// allocate memory
	state = (CRYPTK2)malloc(sizeof(struct _cryptk2));

	return state;
}

// set key and iv to internal state
void CRYPTK2_API cryptk2_setup(CRYPTK2 state, const uint8_t *key, const uint8_t *iv) {
	uint32_t temp;

	// validate arguments
	if (state == NULL || key == NULL || iv == NULL) {
		return;
	}

	// copy iv
	state->iv[0] = pack_uint32(iv[0], iv[1], iv[2], iv[3]);
	state->iv[1] = pack_uint32(iv[4], iv[5], iv[6], iv[7]);
	state->iv[2] = pack_uint32(iv[8], iv[9], iv[10], iv[11]);
	state->iv[3] = pack_uint32(iv[12], iv[13], iv[14], iv[15]);

	// copy and expand key
	state->ik[0] = pack_uint32(key[0], key[1], key[2], key[3]);
	state->ik[1] = pack_uint32(key[4], key[5], key[6], key[7]);
	state->ik[2] = pack_uint32(key[8], key[9], key[10], key[11]);
	state->ik[3] = temp = pack_uint32(key[12], key[13], key[14], key[15]);
	state->ik[4] = state->ik[0] ^ sub((temp << 8) ^ unpack_uint32_first(temp)) ^ 0x01000000;
	state->ik[5] = state->ik[1] ^ state->ik[4];
	state->ik[6] = state->ik[2] ^ state->ik[5];
	state->ik[7] = temp = state->ik[3] ^ state->ik[6];
	state->ik[8] = state->ik[4] ^ sub((temp << 8) ^ unpack_uint32_first(temp)) ^ 0x02000000;
	state->ik[9] = state->ik[5] ^ state->ik[8];
	state->ik[10] = state->ik[6] ^ state->ik[9];
	state->ik[11] = state->ik[7] ^ state->ik[10];

	// set initial state: FSR-A
	state->a[0] = state->ik[4];
	state->a[1] = state->ik[3];
	state->a[2] = state->ik[2];
	state->a[3] = state->ik[1];
	state->a[4] = state->ik[0];

	// set initial state: FSR-B
	state->b[0] = state->ik[10];
	state->b[1] = state->ik[11];
	state->b[2] = state->iv[0];
	state->b[3] = state->iv[1];
	state->b[4] = state->ik[8];
	state->b[5] = state->ik[9];
	state->b[6] = state->iv[2];
	state->b[7] = state->iv[3];
	state->b[8] = state->ik[7];
	state->b[9] = state->ik[5];
	state->b[10] = state->ik[6];

	// zero internal register & counter
	state->cnt = state->l2 = state->l1 = state->r2 = state->r1 = 0;

	// update 24 times
	for (int i=0; i<24; ++i) {
		setup_internal(state);
	}

	// generate pseudo-random number stream
	gen_stream(state);
}


#define BEGIN_CASE if (0);
#define CASE_CRYPTMODE else if (mode == MODE_CRYPT)
#define CASE_STREAMMODE else if (mode == MODE_STREAM)
#define END_CASE else;


// output encrypted data or raw stream
void CRYPTK2_API cryptk2_crypt(CRYPTK2 state, size_t len, const uint8_t *in, uint8_t *out) {
	crypt_internal(state, MODE_CRYPT, len, in, out);
}
void CRYPTK2_API cryptk2_stream(CRYPTK2 state, size_t len, uint8_t *out) {
	crypt_internal(state, MODE_STREAM, len, NULL, out);
}
static inline void crypt_internal(CRYPTK2 state, const enum mode_crypt mode, size_t len, const uint8_t *in, uint8_t *out) {
	size_t first, loop, final, count;
	uint32_t sh, sl;
	uint_fast8_t state_cnt;

	// validate arguments
	BEGIN_CASE
	CASE_CRYPTMODE
	{
		if (state == NULL || len == 0 || in == NULL || out == NULL) {
			return;
		}
	}
	CASE_STREAMMODE
	{
		if (state == NULL || len == 0 || out == NULL) {
			return;
		}
	}
	END_CASE

	// it's faster than look up the structure
	state_cnt = state->cnt;

	// how many bytes will be stored during the first round?
	first = state_cnt ? (8 - state_cnt) : 0;
	if (first > len) {
		first = len;
	}

	// how many times will be performed the main loop?
	loop = (len - first) / 8;

	// how many bytes will be stored during the final round?
	final = (len - first) - loop * 8;


	// first round
	if (state_cnt != 0) {
		uint_fast8_t temp_uint8;
		const uint8_t *vin;
		uint8_t *vout;

		// higher 4 bytes: last 3 bytes of 4 bytes (the first byte will be excluded)
		sh = state->sh;
		// lower 4 bytes
		sl = state->sl;

		temp_uint8 = state_cnt - 1;
		vout = out - temp_uint8;
		count = 0;

		BEGIN_CASE
		CASE_CRYPTMODE
		{
			vin = in - temp_uint8;
			switch (temp_uint8) {
			case 0:
				vout[0] = vin[0] ^ unpack_uint32_second(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 1:
				vout[1] = vin[1] ^ unpack_uint32_third(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 2:
				vout[2] = vin[2] ^ unpack_uint32_last(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 3:
				vout[3] = vin[3] ^ unpack_uint32_first(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 4:
				vout[4] = vin[4] ^ unpack_uint32_second(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 5:
				vout[5] = vin[5] ^ unpack_uint32_third(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			default: // 6
				vout[6] = vin[6] ^ unpack_uint32_last(sl);
				update(state);
				if (++count == first) goto finish_in_first;
			}
			in = vin + 7;
		}
		CASE_STREAMMODE
		{
			switch (temp_uint8) {
			case 0:
				vout[0] = unpack_uint32_second(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 1:
				vout[1] = unpack_uint32_third(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 2:
				vout[2] = unpack_uint32_last(sh);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 3:
				vout[3] = unpack_uint32_first(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 4:
				vout[4] = unpack_uint32_second(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			case 5:
				vout[5] = unpack_uint32_third(sl);
				if (++count == first) goto finish_in_first;
				/*lint -fallthrough */
			default: // 6
				vout[6] = unpack_uint32_last(sl);
				update(state);
				if (++count == first) goto finish_in_first;
			}
		}
		END_CASE

		out = vout + 7;
	}

	// main loop
	for (count=0; count<loop; ++count) {

		BEGIN_CASE
		CASE_CRYPTMODE  { sh = pack_uint32(in[0], in[1], in[2], in[3]) ^ state->sh; }
		CASE_STREAMMODE { sh = state->sh; }
		END_CASE

		out[0] = unpack_uint32_first(sh);
		out[1] = unpack_uint32_second(sh);
		out[2] = unpack_uint32_third(sh);
		out[3] = unpack_uint32_last(sh);

		BEGIN_CASE
		CASE_CRYPTMODE  { sl = pack_uint32(in[4], in[5], in[6], in[7]) ^ state->sl; }
		CASE_STREAMMODE { sl = state->sl; }
		END_CASE

		out[4] = unpack_uint32_first(sl);
		out[5] = unpack_uint32_second(sl);
		out[6] = unpack_uint32_third(sl);
		out[7] = unpack_uint32_last(sl);

		update(state);
		out += 8;

		BEGIN_CASE
		CASE_CRYPTMODE { in += 8; }
		END_CASE

	}

	// final round
	if (final != 0) {
		// higher 4 bytes
		sh = state->sh;
		// lower first 3 bytes 4 bytes (the last byte will be omitted)
		sl = state->sl;

		BEGIN_CASE
		CASE_CRYPTMODE
		{
			switch (final) {
				case 7: out[6] = in[6] ^ unpack_uint32_third(sl);		/*lint -fallthrough */
				case 6: out[5] = in[5] ^ unpack_uint32_second(sl);	/*lint -fallthrough */
				case 5: out[4] = in[4] ^ unpack_uint32_first(sl);		/*lint -fallthrough */
				case 4: out[3] = in[3] ^ unpack_uint32_last(sh);		/*lint -fallthrough */
				case 3: out[2] = in[2] ^ unpack_uint32_third(sh);		/*lint -fallthrough */
				case 2: out[1] = in[1] ^ unpack_uint32_second(sh);	/*lint -fallthrough */
				default: out[0] = in[0] ^ unpack_uint32_first(sh);
			}
		}
		CASE_STREAMMODE
		{
			switch (final) {
				case 7: out[6] = unpack_uint32_third(sl);	/*lint -fallthrough */
				case 6: out[5] = unpack_uint32_second(sl);	/*lint -fallthrough */
				case 5: out[4] = unpack_uint32_first(sl);	/*lint -fallthrough */
				case 4: out[3] = unpack_uint32_last(sh);	/*lint -fallthrough */
				case 3: out[2] = unpack_uint32_third(sh);	/*lint -fallthrough */
				case 2: out[1] = unpack_uint32_second(sh);	/*lint -fallthrough */
				default: out[0] = unpack_uint32_first(sh);
			}
		}
		END_CASE

		state->cnt = final;
	}
	else {
		state->cnt = 0;
	}

	return;

finish_in_first:
	// how many bytes used in this routine
	state->cnt = (state_cnt + first) % 8;
	return;
}

#undef BEGIN_CASE
#undef CASE_CRYPTMODE
#undef CASE_STREAMMODE
#undef END_CASE


// free internal state of k2
void CRYPTK2_API delete_cryptk2(CRYPTK2 state) {
	if (state != NULL) {
		// clear from memory
		memset(state, 0, sizeof(struct _cryptk2));
		free(state);
	}
}


// pack four uint8 into one uint32 (return value)
static inline uint32_t pack_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (a << 24) ^ (b << 16) ^ (c << 8) ^ d;
}

// unpack one uint32 into four uint8 (first, second, third, last)
static inline uint8_t unpack_uint32_first(uint32_t u) {
	return u >> 24;
}
static inline uint8_t unpack_uint32_second(uint32_t u) {
	return (u >> 16) & 0xff;
}
static inline uint8_t unpack_uint32_third(uint32_t u) {
	return (u >> 8) & 0xff;
}
static inline uint8_t unpack_uint32_last(uint32_t u) {
	return u & 0xff;
}


// do multiplicative operation with alpha_0[256]
static inline uint32_t mul_a0(uint32_t u) {
	return (u << 8) ^ ta0[unpack_uint32_first(u)];
}

// do multiplicative operation with alpha_1[256]
static inline uint32_t mul_a1(uint32_t u) {
	return (u << 8) ^ ta1[unpack_uint32_first(u)];
}

// do multiplicative operation with alpha_2[256]
static inline uint32_t mul_a2(uint32_t u) {
	return (u << 8) ^ ta2[unpack_uint32_first(u)];
}

// do multiplicative operation with alpha_3[256]
static inline uint32_t mul_a3(uint32_t u) {
	return (u << 8) ^ ta3[unpack_uint32_first(u)];
}

// do substitution
static inline uint32_t sub(uint32_t u) {
	return ts0[unpack_uint32_last(u)] ^ ts1[unpack_uint32_third(u)] ^ ts2[unpack_uint32_second(u)] ^ ts3[unpack_uint32_first(u)];
}

// non-linear function
static inline uint32_t nlf(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
	return (a + b) ^ c ^ d;
}

// generate pseudo-random number stream and set register
static inline void gen_stream(CRYPTK2 state) {
	state->sh = nlf(state->b[10], state->l2, state->l1, state->a[0]);
	state->sl = nlf(state->b[0], state->r2, state->r1, state->a[4]);
}


#define BEGIN_CASE if (0);
#define CASE_SETUPMODE if (mode == MODE_SETUP)
#define CASE_UPDATEMODE if (mode == MODE_UPDATE)
#define END_CASE else;

// update to the next state
static inline void setup_internal(CRYPTK2 state) {
	update_internal(state, MODE_SETUP);
}
static inline void update(CRYPTK2 state) {
	update_internal(state, MODE_UPDATE);
}
static inline void update_internal(CRYPTK2 state, const enum mode_update mode) {
	uint32_t a, b;
	uint32_t l1, r1, l2, r2;
	uint32_t temp1, temp2;

	r1 = sub(state->l2 + state->b[9]);
	r2 = sub(state->r1);
	l1 = sub(state->r2 + state->b[4]);
	l2 = sub(state->l1);

	// shift register
	a = state->a[0];
	state->a[0] = state->a[1];
	state->a[1] = state->a[2];
	state->a[2] = state->a[3];
	state->a[3] = state->a[4];
	b = state->b[0];
	state->b[0] = state->b[1];
	state->b[1] = state->b[2];
	state->b[2] = state->b[3];
	state->b[3] = state->b[4];
	state->b[4] = state->b[5];
	state->b[5] = state->b[6];
	state->b[6] = state->b[7];
	state->b[7] = state->b[8];
	state->b[8] = state->b[9];
	state->b[9] = state->b[10];

	// update state->a[4]
	temp1 = mul_a0(a);

	BEGIN_CASE
	CASE_SETUPMODE  { state->a[4] = temp1 ^ state->a[2] ^ nlf(b, state->r2, state->r1, state->a[4]); }
	CASE_UPDATEMODE { state->a[4] = temp1 ^ state->a[2]; }
	END_CASE

	// update state->b[10]
	if (state->a[1] & 0x40000000) {
		temp1 = mul_a1(b);
	}
	else {
		temp1 = mul_a2(b);
	}

	if (state->a[1] & 0x80000000) {
		temp2 = mul_a3(state->b[7]);
	}
	else {
		temp2 = state->b[7];
	}

	BEGIN_CASE
	CASE_SETUPMODE  { state->b[10] = temp1 ^ state->b[0] ^ state->b[5] ^ temp2 ^ nlf(state->b[10], state->l2, state->l1, a); }
	CASE_UPDATEMODE { state->b[10] = temp1 ^ state->b[0] ^ state->b[5] ^ temp2; }
	END_CASE

	// copy internal registers
	state->r1 = r1;
	state->r2 = r2;
	state->l1 = l1;
	state->l2 = l2;

	BEGIN_CASE
	CASE_UPDATEMODE { gen_stream(state); }
	END_CASE
}

#undef BEGIN_CASE
#undef CASE_SETUPMODE
#undef CASE_UPDATEMODE
#undef END_CASE


#ifdef __cplusplus
}
#endif
