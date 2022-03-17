#include "trap_handler.h"

#include <iostream>
#include <cstring>


//format1 %#04.4y-%#02.2m-%#02.2lT%#02.2h:%#02.2j:%#02.2k.000+00:00 %b [%W]: %#v\n
//format2 %#04.4y-%#02.2m-%#02.2lT%#02.2h:%#02.2j:%#02.2k.000+00:00 %b [%W]: %#v\n
//format %b  protocol, %W text

/*
bool
realloc_format_plain_trap(u_char ** buf, size_t * buf_len,
                          size_t * out_len, bool allow_realloc,
                          snmp_pdu *pdu)

     /*
      * Function:
      *    Format the trap information in the default way and put the results
      * into the buffer, truncating at the buffer's length limit. This
      * routine returns 1 if the output was completed successfully or
      * 0 if it is truncated due to a memory allocation failure.
      *
      * Input Parameters:
      *    buf, buf_len, out_len, allow_realloc - standard relocatable
      *                                           buffer parameters
      *    pdu       - the pdu information
      */
/*{
        netsnmp_variable_list *vars;        /* variables assoc with trap */    /*
         * Output the PDU variables.
         *//*
        for (vars = pdu->variables; vars != NULL; vars = vars->next_variable) {
            if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) "\t")) {
                return false;
            }
            if (!sprint_realloc_variable(buf, buf_len, out_len, allow_realloc,
                                         vars->name, vars->name_length,
                                         vars)) {
                return false;
            }
            /*if (!snmp_strcat
                    (buf, buf_len, out_len, allow_realloc, (const u_char *) "\n")) {
                    return false;
            }*/

             /*
             * String is already null-terminated.  That's all folks!
             */
           /* return true;
        }
    }*/
/*
 *  Trap handler for logging to a file
 */
bool   print_handler(  snmp_pdu           *pdu)
{
    u_char         *rbuf = NULL;
    size_t          r_len = 64, o_len = 0;

    if ((rbuf = (u_char *) calloc(r_len, 1)) == NULL) {
            std::cout << "couldn't display trap -- malloc failed\n";
            return false;	/* Failed but keep going */
    }
    //bool result = realloc_format_plain_trap(&rbuf, &r_len, &o_len, true,
                                                       //pdu);
    for(size_t i = 0; i < r_len; ++i){
        std::cout << rbuf + i << std::endl;
    }
   // return result;
    return true; //tmp

}
