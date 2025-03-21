Technologies: 
[![My Skills](https://skillicons.dev/icons?i=cpp)](https://skillicons.dev)

RFC 4226                     HOTP Algorithm                December 2005


1.  Overview

   The document introduces first the context around an algorithm that
   generates one-time password values based on HMAC [BCK1] and, thus, is
   named the HMAC-Based One-Time Password (HOTP) algorithm.  In Section
   4, the algorithm requirements are listed and in Section 5, the HOTP
   algorithm is described.  Sections 6 and 7 focus on the algorithm
   security.  Section 8 proposes some extensions and improvements, and
   Section 10 concludes this document.  In Appendix A, the interested
   reader will find a detailed, full-fledged analysis of the algorithm
   security: an idealized version of the algorithm is evaluated, and
   then the HOTP algorithm security is analyzed.

RFC 4226                     HOTP Algorithm                December 2005



   s       resynchronization parameter: the server will attempt to
           verify a received authenticator across s consecutive
           counter values.

   Digit   number of digits in an HOTP value; system parameter.

#Description

   The HOTP algorithm is based on an increasing counter value and a
   static symmetric key known only to the token and the validation
   service.  In order to create the HOTP value, we will use the HMAC-
   SHA-1 algorithm, as defined in RFC 2104 [BCK2].

   As the output of the HMAC-SHA-1 calculation is 160 bits, we must
   truncate this value to something that can be easily entered by a
   user.

                   HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

   Where:

     - Truncate represents the function that converts an HMAC-SHA-1
       value into an HOTP value as defined in Section 5.3.

   The Key (K), the Counter (C), and Data values are hashed high-order
   byte first.

   The HOTP values generated by the HOTP generator are treated as big
   endian.

#Generating an HOTP Value

   We can describe the operations in 3 distinct steps:

   Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS
   is a 20-byte string

   Step 2: Generate a 4-byte string (Dynamic Truncation)
   Let Sbits = DT(HS)   //  DT, defined below,
                        //  returns a 31-bit string

   Step 3: Compute an HOTP value
   Let Snum  = StToNum(Sbits)   // Convert S to a number in
                                    0...2^{31}-1
   Return D = Snum mod 10^Digit //  D is a number in the range
                                    0...10^{Digit}-1

 Example of HOTP Computation for Digit = 6

   The following code example describes the extraction of a dynamic
   binary code given that hmac_result is a byte array with the HMAC-
   SHA-1 result:

        int offset   =  hmac_result[19] & 0xf ;
        int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

   SHA-1 HMAC Bytes (Example)

   -------------------------------------------------------------
   | Byte Number                                               |
   -------------------------------------------------------------
   |00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|
   -------------------------------------------------------------
   | Byte Value                                                |
   -------------------------------------------------------------
   |1f|86|98|69|0e|02|ca|16|61|85|50|ef|7f|19|da|8e|94|5b|55|5a|
   -------------------------------***********----------------++|

