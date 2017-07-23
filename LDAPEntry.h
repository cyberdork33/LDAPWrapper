//
//  LDAPEntry.h
//  LDAPManager
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//
/*!
 @header LDAPEntry.h
 @brief This is the header for the LDAPEntry class.
 @author cyberdork33@gmail.com
 @version 0.9
 @updated 2012-05-14
 */

#import <Foundation/Foundation.h>
#import "LDAPCertificate.h"

/*!
 @class LDAPEntry
 @brief This class provides an ObjectiveC interface for a typical LDAPMessage
 containing data related to a single entry in the LDAP database. See
 the man pages for the LDAP Framework information on LDAPMessage.
 */
@interface LDAPEntry : NSObject

/*!
 @property cn
 @brief The entry's common name field
 */
@property (copy) NSString *cn;

/*!
 @property mail
 @brief An array of all the email attributes within an ldap entry.
 @discussion This NSArray should reliably contain only NSStrings and no other objects.
 */
@property (copy) NSArray *mail;

@property NSInteger defaultEmailEntry;

@property (strong) LDAPCertificate *userCertificate;

/*!
 @property hasCertificate
 @brief This just indicates if there is a certificate present or not for this entry.
 */
@property (readonly) BOOL hasCertificate;

@end
