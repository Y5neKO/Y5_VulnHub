

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for tapsrv.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __tapsrv_h_h__
#define __tapsrv_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __tapsrv_INTERFACE_DEFINED__
#define __tapsrv_INTERFACE_DEFINED__

/* interface tapsrv */
/* [implicit_handle][version][uuid] */ 

typedef /* [context_handle] */ void *PCONTEXT_HANDLE_TYPE;

long ClientAttach( 
    /* [context_handle][out] */ PCONTEXT_HANDLE_TYPE *pphContext,
    /* [in] */ long lProcessID,
    /* [out] */ long *phAsyncEventsEvent,
    /* [string][in] */ const wchar_t *pszDomainUser,
    /* [string][in] */ wchar_t *pszMachine);

void ClientRequest( 
    /* [in] */ PCONTEXT_HANDLE_TYPE phContext,
    /* [size_is][length_is][out][in] */ unsigned char *pBuffer,
    /* [in] */ long lNeededSize,
    /* [out][in] */ long *plUsedSize);

void ClientDetach( 
    /* [out][in] */ PCONTEXT_HANDLE_TYPE *pphContext);


extern handle_t tapsrv_IfHandle;


extern RPC_IF_HANDLE tapsrv_v1_0_c_ifspec;
extern RPC_IF_HANDLE tapsrv_v1_0_s_ifspec;
#endif /* __tapsrv_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER PCONTEXT_HANDLE_TYPE_rundown( PCONTEXT_HANDLE_TYPE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


