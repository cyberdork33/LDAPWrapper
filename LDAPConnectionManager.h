//
//  LDAPConnectionManager.h
//  CertificateFinder
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//

#import <Foundation/Foundation.h>

#import <ldap.h>


@interface LDAPConnectionManager : NSObject

// Error Handling
@property BOOL errorEncountered;
@property (readonly) NSString *lastLDAPError;
- (void)clearError;

// Convienience Initializers
- (LDAPConnectionManager *)initWithhost:(NSString *)host;
- (LDAPConnectionManager *)initWithhost:(NSString *)host port:(NSInteger)port;

- (NSInteger)bindLDAPServer:(NSString *)host port:(NSInteger)port;

// Returns NSArray of LDAPEntry objects
- (NSArray *)searchLDAPBase:(NSString *)baseDN
                    timeout:(NSInteger)searchTime
                     filter:(NSString *)filter
                 attributes:(NSArray *)attributes;

@end
