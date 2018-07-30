using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Reflection;


namespace KerberosAuth
{
    class Program
    {
        static void Main(string[] args)
        {
            //MechType: 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
            //MechType: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
            //MechType: 1.3.6.1.4.1.311.2.2.30 (NEGOEX - SPNEGO Extended Negotiation Security Mechanism)
            //MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
            byte[] MechTypes = {0xa0, 0x30,  0x30, 0x2e ,0x06, 0x09, 0x2a , 0x86 , 0x48 , 0x82 , 0xf7 , 0x12 , 0x01 , 0x02 , 0x02 , 0x06 , 0x09 , 0x2a , 0x86 , 0x48
                , 0x86 , 0xf7 , 0x12 , 0x01 , 0x02 , 0x02 , 0x06 , 0x0a , 0x2b , 0x06 , 0x01 , 0x04 , 0x01 , 0x82 , 0x37 , 0x02
                , 0x02 , 0x1e , 0x06 , 0x0a , 0x2b , 0x06 , 0x01 , 0x04 , 0x01 , 0x82 , 0x37 , 0x02 , 0x02 , 0x0a };

            //OID: 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation)
            byte[] oid = { 0x06 , 0x06 ,0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

            //KRB5 OID: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
            byte[] krb5_oid = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };  


            var url = "http://app1.zf.com/index.html";
            var userName = "user32";
            var paswd = "Testpass";
            var domServer = "server006";
            var domain = domServer + ".zf.com";
            string spn = "HTTP/rocket3210.zf.com@ZF.COM";

            byte[] ticketData;
            string sret = "";

            //Get service ticket from server
            using (var domainContext = new PrincipalContext(ContextType.Domain, domain, null, ContextOptions.Negotiate,
                userName, paswd))
            {
                using (var foundUser = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, userName))
                {

                    Console.WriteLine("User Principale name" + UserPrincipal
                                          .FindByIdentity(domainContext, IdentityType.SamAccountName, userName)
                                          .UserPrincipalName);
                    
                    KerberosSecurityTokenProvider k1 = new KerberosSecurityTokenProvider(spn
                        , System.Security.Principal.TokenImpersonationLevel.Identification, //2248
                        new System.Net.NetworkCredential(userName, paswd, "zf.COM"));
                    KerberosRequestorSecurityToken T1 =
                        k1.GetToken(TimeSpan.FromMinutes(1)) as KerberosRequestorSecurityToken;
                    ticketData = T1.GetRequest();
                    sret = Convert.ToBase64String(ticketData);
                    Console.WriteLine("=====sret========" + sret);
                    Console.WriteLine("=====Time now========" + System.DateTime.UtcNow);
                    Console.WriteLine("=====valir from========" + T1.ValidFrom);
                    Console.WriteLine("=====valir from========" + T1.ValidTo);
                    Console.WriteLine("=====LEN========" + sret.Length);
                }
            }

            #region Decoding service ticket and geting Kerberos service ticket
            
            List<byte> identifier0 = new List<byte>();
            List<byte> dataToken0 = new List<byte>();
            int dataLength0 = AsnDer.Decode(ticketData,identifier0,dataToken0);              //Get GSS-API


            List<byte> identifier10 = new List<byte>();
            List<byte> dataToken10 = new List<byte>();
            int dataLength10 = AsnDer.Decode(dataToken0.ToArray(), identifier10, dataToken10);   //Get OID

            var Kerberos = dataToken0.Skip(dataLength10); //Get KERBEROS data
            #endregion

            #region Creating negotiation request
            var data1 =  AsnDer.Encode(new Byte[] { 0x60 }, krb5_oid.Concat(Kerberos).ToArray());            //krb5_oid + Kerberos service ticket
            var data2 =  AsnDer.Encode(new Byte[] { 0x04 }, data1);                                          //Wrap Sequence of bytes
            var data3 =  AsnDer.Encode(new Byte[] { 0xa2 }, data2);                                          //Wrap MechToken element
            var data4 =  AsnDer.Encode(new Byte[] { 0x30 }, MechTypes.Concat(data3).ToArray());              //Contruct sequence             
            var data5 =  AsnDer.Encode(new Byte[] { 0xa0 }, data4);                                          //NegResult 
            var data6 =  AsnDer.Encode(new Byte[] { 0x60 }, oid.Concat(data5).ToArray());                    //NegTokenInit
            #endregion
            

            CookieContainer cookieContainer = new CookieContainer();
            HttpWebRequest req = HttpWebRequest.Create(url) as HttpWebRequest;
            req.CookieContainer = cookieContainer;
            req.KeepAlive = true;
            req.Headers.Add("Authorization", "Negotiate " + Convert.ToBase64String(data6));

            WebResponse resp = req.GetResponse();
            resp.Close();
            
            var cookies = GetAllCookies(cookieContainer);
        }

        public static CookieCollection GetAllCookies(CookieContainer cookieJar)
        {
            CookieCollection cookieCollection = new CookieCollection();

            Hashtable table = (Hashtable)cookieJar.GetType().InvokeMember("m_domainTable",
                BindingFlags.NonPublic |
                BindingFlags.GetField |
                BindingFlags.Instance,
                null,
                cookieJar,
                new object[] { });

            foreach (var tableKey in table.Keys)
            {
                String str_tableKey = (string)tableKey;

                if (str_tableKey[0] == '.')
                {
                    str_tableKey = str_tableKey.Substring(1);
                }

                SortedList list = (SortedList)table[tableKey].GetType().InvokeMember("m_list",
                    BindingFlags.NonPublic |
                    BindingFlags.GetField |
                    BindingFlags.Instance,
                    null,
                    table[tableKey],
                    new object[] { });

                foreach (var listKey in list.Keys)
                {
                    String url = "https://" + str_tableKey + (string)listKey;
                    cookieCollection.Add(cookieJar.GetCookies(new Uri(url)));
                }
            }

            return cookieCollection;
        }
    }
}
