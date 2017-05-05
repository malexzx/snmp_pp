#include <libsnmp.h>
#include "snmp_pp/snmp_pp.h"
#include <memory>

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

#define COLDSTART "1.3.6.1.6.3.1.1.5.1"
#define PAYLOADID "1.3.6.1.4.1.11.2.16.2"
#define PAYLOAD "SNMP++ Trap Send Test"
#define ENTERPRISE "1.3.6.1.2.1.1.1.2.0.1"

struct trap_sender_impl {
  Snmp_pp::snmp_version version;
  Snmp_pp::UdpAddress address;
  Snmp_pp::CTarget ctarget;             // make a target using the address
  Snmp_pp::UTarget utarget;
  Snmp_pp::OctetStr community;                   // community name
  Snmp_pp::OctetStr securityName;
  Snmp_pp::OctetStr authPassword;
  Snmp_pp::OctetStr privPassword;
  int securityModel;
  int securityLevel;
  Snmp_pp::OctetStr contextName;
  Snmp_pp::OctetStr contextEngineID;
  long int  authProtocol;
  long int  privProtocol;
  int retries;                                  // default retries is 1
  int timeout;                                // default is 1 second

  std::unique_ptr<Snmp_pp::Snmp> snmp;
  std::unique_ptr<Snmp_pp::v3MP> v3_MP;

  trap_sender_impl() :
    version(Snmp_pp::version2c),
    address("172.20.147.97:1620"),
    ctarget(address),
    utarget(address),
    community("public"),
    securityName(""),
    authPassword(""),
    privPassword(""),
    securityModel(SNMP_SECURITY_MODEL_USM),
    securityLevel(SNMP_SECURITY_LEVEL_AUTH_PRIV),
    contextName(""),
    contextEngineID(""),
    authProtocol(SNMP_AUTHPROTOCOL_NONE),
    privProtocol(SNMP_PRIVPROTOCOL_NONE),
    retries(3),
    timeout(1000)  {
  }

  const Snmp_pp::SnmpTarget &get_target() const {
    if (version == Snmp_pp::version3)
      return utarget;
    return ctarget;
  }

  void setup_pdu(Snmp_pp::Pdu *pdu) {
    if (version == Snmp_pp::version3) {
      pdu->set_security_level(securityLevel);
      pdu->set_context_name(contextName);
      pdu->set_context_engine_id(contextEngineID);
    }
  }
};

static void callback(int reason, Snmp_pp::Snmp* snmp, Snmp_pp::Pdu& pdu, Snmp_pp::SnmpTarget& target, void* cd) {
  Vb nextVb;
  int pdu_error;

  cout << "XXX reason: " << reason << endl
       << "msg: " << snmp->error_msg(reason) << endl;

  pdu_error = pdu.get_error_status();
  if (pdu_error){
    cout << "Response contains error: "
         << snmp->error_msg(pdu_error)<< endl;
  }
  for (int i=0; i<pdu.get_vb_count(); i++)
  {
    pdu.get_vb(nextVb, i);

    cout << "Oid: " << nextVb.get_printable_oid() << endl
         << "Val: " <<  nextVb.get_printable_value() << endl;
  }

  cout << endl;

}

int main(int argc, char **argv)
{

#if !defined(_NO_LOGGING) && !defined(WITH_LOG_PROFILES)
   // Set filter for logging
   DefaultLog::log()->set_filter(ERROR_LOG, 7);
   DefaultLog::log()->set_filter(WARNING_LOG, 7);
   DefaultLog::log()->set_filter(EVENT_LOG, 7);
   DefaultLog::log()->set_filter(INFO_LOG, 7);
   DefaultLog::log()->set_filter(DEBUG_LOG, 0);
#endif

   Snmp::socket_startup();  // Initialize socket subsystem

   trap_sender_impl ctx;

   //UdpAddress address( "127.0.0.1");      // make a SNMP++ Generic address
   //if ( !address.valid()) {           // check validity of address
	  //cout << "Invalid Address or DNS Name, " << argv[1] << "\n";
   //   return 1;
   //}
   Oid oid( COLDSTART);    // default is ColdStart 

   //---------[ determine options to use ]-----------------------------------
   int retries=1;                                  // default retries is 1
   int timeout=100;                                // default is 1 second
   u_short port=162;                               // default snmp port is 161
   OctetStr community("public");                   // community name
   Oid ent(ENTERPRISE);                            // default enterprise


   OctetStr privPassword("");
   OctetStr authPassword("");
   OctetStr securityName("");
   int securityModel = SNMP_SECURITY_MODEL_USM;
   int securityLevel = SNMP_SECURITY_LEVEL_AUTH_PRIV;
   OctetStr contextName("");
   OctetStr contextEngineID("");
   long authProtocol = SNMP_AUTHPROTOCOL_NONE;
   long privProtocol = SNMP_PRIVPROTOCOL_NONE;
   v3MP *v3_MP;

   Snmp_pp::snmp_version version = version2c;
    authProtocol = SNMP_AUTHPROTOCOL_HMACSHA;
    privProtocol = SNMP_PRIVPROTOCOL_AES128;
    securityName = "informtest";
    contextName  = "informtest";
    authPassword = "mypassword";
    privPassword = "mypassword";

    ctx.address.set_port(port);
    //CTarget ctarget(address);             // make a target using the address
    //UTarget utarget(address);

    if (version == version3) {
      ctx.utarget.set_version(version);          // set the SNMP version SNMPV1 or V2 or V3
      ctx.utarget.set_retry(retries);            // set the number of auto retries
      ctx.utarget.set_timeout(timeout);          // set timeout
      ctx.utarget.set_security_model(securityModel);
      ctx.utarget.set_security_name(securityName);
    }
    else {
      ctx.ctarget.set_version(version);         // set the SNMP version SNMPV1 or V2
      ctx.ctarget.set_retry(retries);           // set the number of auto retries
      ctx.ctarget.set_timeout(timeout);         // set timeout
      ctx.ctarget.set_readcommunity(community); // set the read community name
    }
    
  //----------[ create a SNMP++ session ]-----------------------------------
   int status;
   Snmp *snmp;

   if (ctx.address.get_ip_version() == Address::version_ipv4)
     snmp = new Snmp(status, "0.0.0.0");
   else
     snmp = new Snmp(status, "::");

   if ( status != SNMP_CLASS_SUCCESS) {
      cout << "SNMP++ Session Create Fail, " << snmp->error_msg(status) << "\n";
      return 1;
   }

   //---------[ init SnmpV3 ]--------------------------------------------

   if (version == version3) {
     const char *engineId = "InformSender";
     const char *filename = "snmpv3_boot_counter";
     unsigned int snmpEngineBoots = 0;
     int status;

     status = getBootCounter(filename, engineId, snmpEngineBoots);
     if ((status != SNMPv3_OK) && (status < SNMPv3_FILEOPEN_ERROR))
     {
       cout << "Error loading snmpEngineBoots counter: " << status << endl;
       return 1;
     }
     snmpEngineBoots++;
     status = saveBootCounter(filename, engineId, snmpEngineBoots);
     if (status != SNMPv3_OK)
     {
       cout << "Error saving snmpEngineBoots counter: " << status << endl;
       return 1;
     }

     int construct_status;
     v3_MP = new v3MP(engineId, snmpEngineBoots, construct_status);
     if (construct_status != SNMPv3_MP_OK)
     {
       cout << "Error initializing v3MP: " << construct_status << endl;
       return 1;
     }

     USM *usm = v3_MP->get_usm();
     usm->add_usm_user(securityName,
		       authProtocol, privProtocol,
		       authPassword, privPassword);
   }
   else
   {
     // MUST create a dummy v3MP object if _SNMPv3 is enabled!
     int construct_status;
     v3_MP = new v3MP("dummy", 0, construct_status);
   }

   // Start thread that triggers processing of async responses
   snmp->start_poll_thread(10);


for(int k=0;k<10000;k++){
for(int zz=0;zz<100;zz++){
  //--------[ build up SNMP++ object needed ]-------------------------------
  Pdu pdu;                               // construct a Pdu object
  Vb vb;                                 // variable binding object to use
  vb.set_oid(PAYLOADID);                 // example oid for trap payload
  vb.set_value(PAYLOAD);                 // example string for payload
  pdu += vb;                             // append the vb to the pdu
  pdu.set_notify_id(oid);               // set the id of the trap
  pdu.set_notify_enterprise(ent);       // set up the enterprise of the trap
  if (version == version3) {
    pdu.set_security_level(securityLevel);
    pdu.set_context_name(contextName);
    pdu.set_context_engine_id(contextEngineID);
  }

   //-------[ Send the trap  ]------------------------------------------------
   cout << "SNMP++ Trap to  SNMPV"
        << ((version==version3) ? (version) : (version+1));
   if (version == version3)
     cout << endl
          << "securityName= " << securityName.get_printable()
          << ", securityLevel= " << securityLevel
          << ", securityModel= " << securityModel << endl
          << "contextName= " << contextName.get_printable()
          << ", contextEngineID= " << contextEngineID.get_printable()
          << endl;
   else
     cout << " Community=" << community.get_printable() << endl << flush;

   SnmpTarget *target;
   if (version == version3)
     target = &ctx.utarget;
   else
     target = &ctx.ctarget;

   status = snmp->inform( pdu, *target, callback, 0);
   if (status == SNMP_CLASS_SUCCESS)
   {
     cout << "Async GetNext Request sent." << endl;
   }
   else
     cout << "SNMP++ GetNext Error, " << snmp->error_msg( status)
	  << " (" << status <<")" << endl ;

/*
   if (status == SNMP_CLASS_SUCCESS)
   {
     pdu.get_vb( vb,0);
     if (pdu.get_type() == REPORT_MSG) {
       cout << "Received a report pdu: "
            << snmp->error_msg(vb.get_printable_oid()) << endl;
     }
     cout << "Oid = " << vb.get_printable_oid() << endl
	  << "Value = " << vb.get_printable_value() << endl;
     //pdu.get_context_engine_id(contextEngineID);
   }
   else
   {
     cout << "SNMP++ Inform Error, " << snmp->error_msg( status)
	  << " (" << status <<")" << endl ;
   }
   std::cout << "================================================================" << std::endl;
*/
   //usleep(100);

}
 usleep(0);
}
   for(int i=0;i<10;i++)
           usleep(100000);

   snmp->stop_poll_thread(); // stop poll thread

   Snmp::socket_cleanup();  // Shut down socket subsystem
}



