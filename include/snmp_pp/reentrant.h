/*_############################################################################
  _## 
  _##  reentrant.h  
  _##
  _##  SNMP++ v3.3
  _##  -----------------------------------------------
  _##  Copyright (c) 2001-2013 Jochen Katz, Frank Fock
  _##
  _##  This software is based on SNMP++2.6 from Hewlett Packard:
  _##  
  _##    Copyright (c) 1996
  _##    Hewlett-Packard Company
  _##  
  _##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  _##  Permission to use, copy, modify, distribute and/or sell this software 
  _##  and/or its documentation is hereby granted without fee. User agrees 
  _##  to display the above copyright notice and this license notice in all 
  _##  copies of the software and any documentation of the software. User 
  _##  agrees to assume all liability for the use of the software; 
  _##  Hewlett-Packard and Jochen Katz make no representations about the 
  _##  suitability of this software for any purpose. It is provided 
  _##  "AS-IS" without warranty of any kind, either express or implied. User 
  _##  hereby grants a royalty-free license to any and all derivatives based
  _##  upon this software code base. 
  _##  
  _##########################################################################*/
// $Id: reentrant.h 2359 2013-05-09 20:07:01Z fock $

#ifndef _reentrant_h_
#define _reentrant_h_

#include "snmp_pp/config_snmp_pp.h"
#include "snmp_pp/smi.h"

#include "cpp11om/lwlock.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

typedef cpp11om::NonRecursiveLWLock SnmpSynchronized;
typedef cpp11om::LockGuard<SnmpSynchronized> SnmpSynchronize;

#define REENTRANT(x) { SnmpSynchronize _synchronize(*this); x }

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif

