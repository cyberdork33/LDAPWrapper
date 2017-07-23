//
//  LDAPConnectionManager.m
//  CertificateFinder
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//

#import "LDAPConnectionManager.h"
#import "LDAPEntry.h"

@interface LDAPConnectionManager()

/* PRIVATE PROPERTIES */
@property LDAP *ldapObject;
@property LDAPMessage *searchResults;

@end

@implementation LDAPConnectionManager

/* PUBLIC PROPERTIES */
@synthesize errorEncountered = _errorEncountered;
@synthesize lastLDAPError = _lastLDAPError;

/* PRIVATE PROPERTIES */
@synthesize ldapObject = _ldapObject;
@synthesize searchResults = _searchResults;

/* PUBLIC METHODS */
- (void)clearError {
  _lastLDAPError = nil;
  self.errorEncountered = false;
}

- (NSInteger)bindLDAPServer:(NSString *)host port:(NSInteger)port {

    // check for invalid host information
    if ([host cStringUsingEncoding:NSASCIIStringEncoding] == NULL) {
        NSLog(@"Specified LDAP host contains non-ASCII characters");
        return 2;
    }

    // Variable to handle ldap function error messages.
	int ldapError;

	// Get a handle to an LDAP connection and set any session preferences.
    NSString *ldapURI = [NSString stringWithFormat:@"ldap://%@:%ld",host, port];
    NSLog(@"Connecting to %@", ldapURI);
    ldapError = ldap_initialize(&_ldapObject, [ldapURI cStringUsingEncoding:NSASCIIStringEncoding]);
    if (ldapError != LDAP_SUCCESS) {
        NSLog(@"LDAP Initialization Failed: %s", ldap_err2string(ldapError));
        return 1;
    }

    // NOTE: Could not get the bind to work,
    // but everything else still seems to work without...

	// Bind, anonymously, to the server.
    //ldapError = ldap_simple_bind_s(self.ldapObject, NULL, NULL);
    //    ldapError = ldap_sasl_bind_s(self.ldapObject, NULL, NULL, NULL, NULL, NULL, NULL);
    //    if (ldapError != LDAP_SUCCESS) {
    //        NSLog(@"LDAP Bind Failed: %s", ldap_err2string(ldapError));
    //        return 2;
    //    }

    // Success!
	return 0;
}

- (NSArray *)searchLDAPBase:(NSString *)baseDN
                    timeout:(NSInteger)searchTime
                     filter:(NSString *)filter
                 attributes:(NSArray *)attributes {

    // Check for a valid search base
    if ([baseDN cStringUsingEncoding:NSASCIIStringEncoding] == NULL) {
        NSLog(@"Error: LDAP search base contains non-ASCII characters");
        return nil;
    }

    // Check for bad characters in filter
    if ([filter cStringUsingEncoding:NSASCIIStringEncoding] == NULL) {
        NSLog(@"Error: LDAP search filter contains non-ASCII characters");
        return nil;
    }

    // Verify attributes array contains only strings.
    // Otherwise it is pointless to continue.
    for (id object in attributes) {
        if (![object isKindOfClass:[NSString class]]) {
            NSLog(@"Error: Non-NSString object found in attributes array.");
            return nil;
        }
    }

    // We have to take the desired attributes from the NSArray and put them in a
    // char** array so that they can be passed to the ldap_search function(s).
    // First create the char** array of appropriate size.
    char **cAttributes = (char **)malloc(sizeof(char *) * (attributes.count + 1));

    int i;
    for(i = 0; i < attributes.count; i++) {
        NSString *attribute = [attributes objectAtIndex:i];
        const char *cString = [attribute cStringUsingEncoding:NSASCIIStringEncoding];
        long cStringLength = strlen(cString);
        // C Strings (char *) have to be null-terminated!
        char *cstr_copy = (char *)malloc(sizeof(char) * (cStringLength + 1));
        strcpy(cstr_copy, cString); // Copying to make sure values are clean
        cAttributes[i] = cstr_copy;
    }
    cAttributes[i] = NULL;

    // Setup structure to govern how long to search the directory
    struct timeval timevalStruct;
    timevalStruct.tv_usec = 0;
    if (searchTime <= 0) {
        NSLog(@"Warning: Timeout value must be greater than 0! Defaulting to 60 seconds.");
        timevalStruct.tv_sec = 60;
    } else {
        timevalStruct.tv_sec = searchTime;
    }

    // Perform search!
    int ldapError;
    ldapError = ldap_search_ext_s(self.ldapObject,
                                  [baseDN cStringUsingEncoding:NSASCIIStringEncoding],
                                  LDAP_SCOPE_SUBTREE,
                                  [filter cStringUsingEncoding:NSASCIIStringEncoding],
                                  cAttributes,
                                  0,
                                  NULL,
                                  NULL,
                                  &timevalStruct,
                                  0,
                                  &_searchResults);

    // Handle any errors
    if ( ldapError != LDAP_SUCCESS ) {
        NSLog(@"LDAP Search Error: %s", ldap_err2string(ldapError));
        self.errorEncountered = true;
        _lastLDAPError = [NSString stringWithFormat:@"%s", ldap_err2string(ldapError)];
        return nil;
    }

    // Cleanup the char** mess that we created!
    for(i = 0; i < [attributes count]; i++) {
        free(cAttributes[i]);
    }
    free(cAttributes);

    // Create mutable version of function return variable
    NSMutableArray *results = [[NSMutableArray alloc] init];

    // Iterate through the entries in the ldapResults
    LDAPMessage *resultEntry;
    for (resultEntry = ldap_first_entry(self.ldapObject, self.searchResults);
         resultEntry != NULL;
         resultEntry = ldap_next_entry(self.ldapObject, resultEntry)) {

        // Object to hold LDAP data.
        LDAPEntry *entryResults = [[LDAPEntry alloc] init];
        entryResults.defaultEmailEntry = 0;

        // Iterate thorugh requested attributes and handle accordingly
        for (NSString *attribute in attributes) {
            // Common Name
            if ([attribute isEqualToString:@"cn"]) {

                struct berval **values;
                char *longest = "";

                values = ldap_get_values_len(self.ldapObject, resultEntry, "cn");
                int n;
                for (n = 0; n < ldap_count_values_len(values); n++) {
                    if (strlen(longest) < strlen(values[n]->bv_val)) {
                        longest = values[n]->bv_val;
                    }
                }
                NSString *cn = [NSString stringWithCString:longest
                                                  encoding:NSASCIIStringEncoding];
                entryResults.cn = cn;
                ldap_value_free_len(values);

            // User Certificate
            } else if ([attribute isEqualToString:@"userCertificate;binary"]) {

                // Get the binary certificate data
                struct berval **binaryValues; // Defined in LDAP headers
                binaryValues = ldap_get_values_len(self.ldapObject, resultEntry, "userCertificate;binary");

                // Make sure we got something, and it is in binary format.
                if ((binaryValues == NULL) || ((binaryValues[0]->bv_len >= 4) && (strncmp("{ASN}", binaryValues[0]->bv_val, 4) == 0))) {

                    //NSLog(@"Invalid certificate data retrieved from directory.");
                    entryResults.userCertificate.userCertificateData = nil;
                } else {

                    //NSData *certData = [NSData dataWithBytes:(uint8 *)binaryValues[0]->bv_val length:binaryValues[0]->bv_len];
                    NSData *certData = [NSData dataWithBytes:(uint *)binaryValues[0]->bv_val length:binaryValues[0]->bv_len];
                    // Attempt to use a type that is compatible with iOS.

                    entryResults.userCertificate.userCertificateData = certData;
                }

                ldap_value_free_len(binaryValues);

            // Email Addresses
            } else if ([attribute isEqualToString:@"mail"]) {

                //char **values;
                struct berval **values;
                values = ldap_get_values_len(self.ldapObject, resultEntry, "mail");
                if ((values == NULL) || (ldap_count_values_len(values) == 0)) {

                    //NSLog(@"No Emails returned from directory.");
                    entryResults.mail = nil;
                } else {

                    NSMutableArray *emails = [[NSMutableArray alloc]init];
                    int n;
                    for (n = 0; n < ldap_count_values_len(values); n++) {

                        NSString *email = [NSString stringWithCString:values[n]->bv_val encoding:NSASCIIStringEncoding];
                        [emails addObject:email];
                    }
                    entryResults.mail = emails.copy;
                }
                ldap_value_free_len(values);

            } else {
                NSLog(@"Encountered Unhandled LDAP Attribute: '%@'", attribute);
            }
        }
        [results addObject:entryResults];
        entryResults = nil;
    }

    // Return result
    return results.copy;
}

/* OBJECT LIFECYCLE */
- (LDAPConnectionManager *)initWithhost:(NSString *)host {

    if (self = [self init]) {
        [self bindLDAPServer:host port:389];
    }
    return self;
}
- (LDAPConnectionManager *)initWithhost:(NSString *)host port:(NSInteger)port {

    if (self = [self init]) {
        // This object's custom initialization
        [self bindLDAPServer:host port:port];
    }
    return self;
}
- (void)dealloc {
    if (self.ldapObject != NULL) {
        //ldap_unbind(self.ldapObject);
    }
}
@end
