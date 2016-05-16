//
// Lockbox.m
//
// Created by Mark H. Granoff on 4/19/12.
// Copyright (c) 2012 Hawk iMedia. All rights reserved.
//

#import "Lockbox.h"
#import <Security/Security.h>

// Define DLog if user hasn't already defined his own implementation
#ifndef DLog
#ifdef DEBUG
#define DLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ## __VA_ARGS__);
#else
#define DLog(...)
#endif
#endif

#define kDelimiter @"-|-"
#define DEFAULT_ACCESSIBILITY kSecAttrAccessibleWhenUnlocked

#define LOCKBOX_ID __bridge id
#define LOCKBOX_DICTREF __bridge CFDictionaryRef

#define k_userAccountInfoKey @"userAccountInfoKey"
#define k_userIdKeyName @"userId"
#define k_firstNameKeyName @"firstName"
#define k_lastNameKeyName @"lastName"
#define k_badgeNumberKeyName @"badgeNumber"
#define k_organizationNameKeyName @"organizationName"
#define k_organizationStateKeyName @"organizationState"
#define k_organizationCountryKeyName @"organizationCountry"
#define k_organizationCityKeyName @"organizationCity"
#define k_organizationAddressKeyName @"organizationAddress"
#define k_userFolderGUIDKeyName @"userFolderGUID"
#define k_userRealmEncryptionKeyName @"realmEncryptionKey"
#define k_userFileEncryptionKeyName @"fileEncryptionKey"
#define k_userHashPasswordKeyName @"userHashPassword"
#define k_userPasswordKeyName @"userPassword"
#define k_appHashedUUIDKeyName @"appHashedUUID"
#define k_appLastUser @"appLastUser"

static Lockbox *_lockBox = nil;
static NSString *_defaultKeyPrefix = nil;

@interface Lockbox ()
@property (strong, nonatomic, readwrite) NSString *keyPrefix;
@end

@implementation Lockbox

+ (void)initialize
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _defaultKeyPrefix = [[[NSBundle bundleForClass:[self class]] infoDictionary] objectForKey:(NSString*)kCFBundleIdentifierKey];
        _lockBox = [[Lockbox alloc] init];
    });
}



- (instancetype)init
{
    self = [super init];
    if (self)
    {
        self.keyPrefix = _defaultKeyPrefix;
    }

    return self;
}



- (instancetype)initWithKeyPrefix:(NSString *)keyPrefix
{
    self = [self init];
    if (self)
    {
        if (keyPrefix)
        {
            self.keyPrefix = keyPrefix;
        }
    }

    return self;
}



- (NSMutableDictionary *)_service
{
    NSMutableDictionary*dict = [NSMutableDictionary dictionary];

    [dict setObject:(LOCKBOX_ID) kSecClassGenericPassword forKey:(LOCKBOX_ID) kSecClass];

    return dict;
}



- (NSMutableDictionary *)_query
{
    NSMutableDictionary*query = [NSMutableDictionary dictionary];

    [query setObject:(LOCKBOX_ID) kSecClassGenericPassword forKey:(LOCKBOX_ID) kSecClass];
    [query setObject:(LOCKBOX_ID) kCFBooleanTrue forKey:(LOCKBOX_ID) kSecReturnData];

    return query;
}



// Prefix a bare key like "MySecureKey" with the bundle id, so the actual key stored
// is unique to this app, e.g. "com.mycompany.myapp.MySecretKey"
- (NSString *)_hierarchicalKey:(NSString *)key
{
    return [_keyPrefix stringByAppendingFormat:@".%@", key];
}



- (BOOL)setObject:(NSString *)obj forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    NSString *hierKey = [self _hierarchicalKey:key];

    // If the object is nil, delete the item
    if (!obj)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        _lastStatus = SecItemDelete((LOCKBOX_DICTREF)query);
        return (_lastStatus == errSecSuccess);
    }

    NSMutableDictionary *dict = [self _service];
    [dict setObject:hierKey forKey:(LOCKBOX_ID) kSecAttrService];
    [dict setObject:(LOCKBOX_ID)(accessibility) forKey:(LOCKBOX_ID) kSecAttrAccessible];
    [dict setObject:[obj dataUsingEncoding:NSUTF8StringEncoding] forKey:(LOCKBOX_ID) kSecValueData];

    _lastStatus = SecItemAdd ((LOCKBOX_DICTREF) dict, NULL);
    if (_lastStatus == errSecDuplicateItem)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        _lastStatus = SecItemDelete((LOCKBOX_DICTREF)query);
        if (_lastStatus == errSecSuccess)
        {
            _lastStatus = SecItemAdd((LOCKBOX_DICTREF) dict, NULL);
        }
    }

    if (_lastStatus != errSecSuccess)
    {
        DLog(@"SecItemAdd failed for key %@: %d", hierKey, (int)_lastStatus);
    }

    return (_lastStatus == errSecSuccess);
}



- (NSString *)objectForKey:(NSString *)key
{
    NSString *hierKey = [self _hierarchicalKey:key];

    NSMutableDictionary *query = [self _query];
    [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];

    CFDataRef data = nil;
    _lastStatus =
        SecItemCopyMatching ( (LOCKBOX_DICTREF) query, (CFTypeRef *) &data );
    if (_lastStatus != errSecSuccess && _lastStatus != errSecItemNotFound)
    {
        DLog(@"SecItemCopyMatching failed for key %@: %d", hierKey, (int)_lastStatus);
    }

    if (!data)
    {
        return nil;
    }

    NSString *s = [[NSString alloc] initWithData:(__bridge_transfer NSData *)data encoding:NSUTF8StringEncoding];

    return s;
}



- (BOOL)setData:(NSData *)obj forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    NSString *hierKey = [self _hierarchicalKey:key];

    // If the object is nil, delete the item
    if (!obj)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        _lastStatus = SecItemDelete((LOCKBOX_DICTREF)query);
        return (_lastStatus == errSecSuccess);
    }

    NSMutableDictionary *dict = [self _service];
    [dict setObject:hierKey forKey:(LOCKBOX_ID) kSecAttrService];
    [dict setObject:(LOCKBOX_ID)(accessibility) forKey:(LOCKBOX_ID) kSecAttrAccessible];
    [dict setObject:obj forKey:(LOCKBOX_ID) kSecValueData];

    _lastStatus = SecItemAdd ((LOCKBOX_DICTREF) dict, NULL);
    if (_lastStatus == errSecDuplicateItem)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        _lastStatus = SecItemDelete((LOCKBOX_DICTREF)query);
        if (_lastStatus == errSecSuccess)
        {
            _lastStatus = SecItemAdd((LOCKBOX_DICTREF) dict, NULL);
        }
    }

    if (_lastStatus != errSecSuccess)
    {
        DLog(@"SecItemAdd failed for key %@: %d", hierKey, (int)_lastStatus);
    }

    return (_lastStatus == errSecSuccess);
}



- (NSData *)dataForKey:(NSString *)key
{
    NSString *hierKey = [self _hierarchicalKey:key];

    NSMutableDictionary *query = [self _query];
    [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];

    CFDataRef data = nil;
    _lastStatus =
        SecItemCopyMatching ( (LOCKBOX_DICTREF) query, (CFTypeRef *) &data );
    if (_lastStatus != errSecSuccess && _lastStatus != errSecItemNotFound)
    {
        DLog(@"SecItemCopyMatching failed for key %@: %d", hierKey, (int)_lastStatus);
    }

    if (!data)
    {
        return nil;
    }

    return (__bridge_transfer NSData *)data;
}



- (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key
{
    return [self archiveObject:object forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    NSMutableData *data = [NSMutableData new];
    NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initForWritingWithMutableData:data];
    [archiver encodeObject:object forKey:key];
    [archiver finishEncoding];

    return [self setData:data forKey:key accessibility:accessibility];
}



- (id)unarchiveObjectForKey:(NSString *)key
{
    NSData *data = [self dataForKey:key];
    if (!data)
    {
        return nil;
    }

    id object = nil;
    @try
    {
        NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingWithData:data];
        object = [unarchiver decodeObjectForKey:key];
    }
    @catch (NSException *exception) {
        DLog(@"failed for key %@: %@", key, exception.description);
    }

    return object;
}



- (BOOL)setString:(NSString *)value forKey:(NSString *)key
{
    return [self setString:value forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)setString:(NSString *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [self setObject:value forKey:key accessibility:accessibility];
}



- (NSString *)stringForKey:(NSString *)key
{
    return [self objectForKey:key];
}



- (BOOL)setArray:(NSArray *)value forKey:(NSString *)key
{
    return [self setArray:value forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)setArray:(NSArray *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    NSString *components = nil;
    if (value != nil && value.count > 0)
    {
        components = [value componentsJoinedByString:kDelimiter];
    }

    return [self setObject:components forKey:key accessibility:accessibility];
}



- (NSArray *)arrayForKey:(NSString *)key
{
    NSArray *array = nil;
    NSString *components = [self objectForKey:key];
    if (components)
    {
        array = [NSArray arrayWithArray:[components componentsSeparatedByString:kDelimiter]];
    }

    return array;
}



- (BOOL)setSet:(NSSet *)value forKey:(NSString *)key
{
    return [self setSet:value forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)setSet:(NSSet *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [self setArray:[value allObjects] forKey:key accessibility:accessibility];
}



- (NSSet *)setForKey:(NSString *)key
{
    NSSet *set = nil;
    NSArray *array = [self arrayForKey:key];
    if (array)
    {
        set = [NSSet setWithArray:array];
    }

    return set;
}



- (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key
{
    return [self setDictionary:value forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    NSMutableArray *keysAndValues = [NSMutableArray arrayWithArray:value.allKeys];
    [keysAndValues addObjectsFromArray:value.allValues];

    return [self setArray:keysAndValues forKey:key accessibility:accessibility];
}



- (NSDictionary *)dictionaryForKey:(NSString *)key
{
    NSArray *keysAndValues = [self arrayForKey:key];

    if (!keysAndValues || keysAndValues.count == 0)
    {
        return nil;
    }

    if ((keysAndValues.count % 2) != 0)
    {
        DLog(@"Dictionary for %@ was not saved properly to keychain", key);
        return nil;
    }

    NSUInteger half = keysAndValues.count / 2;
    NSRange keys = NSMakeRange(0, half);
    NSRange values = NSMakeRange(half, half);
    return [NSDictionary dictionaryWithObjects:[keysAndValues subarrayWithRange:values]
                                       forKeys:[keysAndValues subarrayWithRange:keys]];
}



- (BOOL)setDate:(NSDate *)value forKey:(NSString *)key
{
    return [self setDate:value forKey:key accessibility:DEFAULT_ACCESSIBILITY];
}



- (BOOL)setDate:(NSDate *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    if (!value)
    {
        return [self setObject:nil forKey:key accessibility:accessibility];
    }

    NSNumber *rti = [NSNumber numberWithDouble:[value timeIntervalSinceReferenceDate]];
    return [self setObject:[rti stringValue] forKey:key accessibility:accessibility];
}



- (NSDate *)dateForKey:(NSString *)key
{
    NSString *dateString = [self objectForKey:key];
    if (dateString)
    {
        return [NSDate dateWithTimeIntervalSinceReferenceDate:[dateString doubleValue]];
    }

    return nil;
}



#pragma mark - Class methods

+ (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key
{
    return [_lockBox archiveObject:object forKey:key];
}



+ (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [_lockBox archiveObject:object forKey:key accessibility:accessibility];
}



+ (id)unarchiveObjectForKey:(NSString *)key
{
    return [_lockBox unarchiveObjectForKey:key];
}



+ (BOOL)setString:(NSString *)value forKey:(NSString *)key
{
    return [_lockBox setString:value forKey:key];
}



+ (BOOL)setString:(NSString *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [_lockBox setString:value forKey:key accessibility:accessibility];
}



+ (NSString *)stringForKey:(NSString *)key
{
    return [_lockBox stringForKey:key];
}



+ (BOOL)setArray:(NSArray *)value forKey:(NSString *)key
{
    return [_lockBox setArray:value forKey:key];
}



+ (BOOL)setArray:(NSArray *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility;
{
    return [_lockBox setArray:value forKey:key accessibility:accessibility];
}

+ (NSArray *)arrayForKey:(NSString *)key
{
    return [_lockBox arrayForKey:key];
}



+ (BOOL)setSet:(NSSet *)value forKey:(NSString *)key
{
    return [_lockBox setSet:value forKey:key];
}



+ (BOOL)setSet:(NSSet *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [_lockBox setSet:value forKey:key accessibility:accessibility];
}



+ (NSSet *)setForKey:(NSString *)key
{
    return [_lockBox setForKey:key];
}



+ (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key
{
    return [_lockBox setDictionary:value forKey:key];
}



+ (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [_lockBox setDictionary:value forKey:key accessibility:accessibility];
}



+ (NSDictionary *)dictionaryForKey:(NSString *)key
{
    return [_lockBox dictionaryForKey:key];
}



+ (BOOL)setDate:(NSDate *)value forKey:(NSString *)key
{
    return [_lockBox setDate:value forKey:key];
}



+ (BOOL)setDate:(NSDate *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility
{
    return [_lockBox setDate:value forKey:key accessibility:accessibility];
}



+ (NSDate *)dateForKey:(NSString *)key
{
    return [_lockBox dateForKey:key];
}



// code for our own project

+ (void)saveLastUser:(NSString *)lastUser
{
    [self archiveObject:lastUser forKey:k_appLastUser];
}



+ (void)saveUserId:(NSString *)userId forUsername:(NSString *)username
{
    [self saveToLockbox:userId forUsername:username keyName:k_userIdKeyName];
}



+ (void)saveFirstName:(NSString *)firstName forUsername:(NSString *)username
{
    [self saveToLockbox:firstName forUsername:username keyName:k_firstNameKeyName];
}



+ (void)saveLastName:(NSString *)lastName forUsername:(NSString *)username
{
    [self saveToLockbox:lastName forUsername:username keyName:k_lastNameKeyName];
}



+ (void)saveBadgeNumber:(NSString *)badgeNumber forUsername:(NSString *)username
{
    [self saveToLockbox:badgeNumber forUsername:username keyName:k_badgeNumberKeyName];
}



+ (void)saveOrganizationName:(NSString *)organizationName forUsername:(NSString *)username
{
    [self saveToLockbox:organizationName forUsername:username keyName:k_organizationNameKeyName];
}



+ (void)saveOrganizationState:(NSString *)organizationState forUsername:(NSString *)username
{
    [self saveToLockbox:organizationState forUsername:username keyName:k_organizationStateKeyName];
}



+ (void)saveOrganizationCountry:(NSString *)organizationCountry forUsername:(NSString *)username
{
    [self saveToLockbox:organizationCountry forUsername:username keyName:k_organizationCountryKeyName];
}



+ (void)saveOrganizationCity:(NSString *)organizationCity forUsername:(NSString *)username
{
    [self saveToLockbox:organizationCity forUsername:username keyName:k_organizationCityKeyName];
}



+ (void)saveOrganizationAddress:(NSString *)organizationAddress forUsername:(NSString *)username
{
    [self saveToLockbox:organizationAddress forUsername:username keyName:k_organizationAddressKeyName];
}



+ (void)saveRealmEncryptionKey:(NSString *)encryptionKey forUsername:(NSString *)username
{
    [self saveToLockbox:encryptionKey forUsername:username keyName:k_userRealmEncryptionKeyName];
}



+ (void)saveUserFolderGUID:(NSString *)folderGUID forUsername:(NSString *)username
{
    [self saveToLockbox:folderGUID forUsername:username keyName:k_userFolderGUIDKeyName];
}



+ (void)saveUserHashPassword:(NSString *)hashPassword forUsername:(NSString *)username
{
    [self saveToLockbox:hashPassword forUsername:username keyName:k_userHashPasswordKeyName];
}



+ (void)saveUserFileEncryptionKey:(NSString *)encryptionKey forUsername:(NSString *)username
{
    [self saveToLockbox:encryptionKey forUsername:username keyName:k_userFileEncryptionKeyName];
}



+ (void)saveUserPassword:(NSString *)userPassword forUsername:(NSString *)username
{
    [self saveToLockbox:userPassword forUsername:username keyName:k_userPasswordKeyName];
}



+ (void)saveHashedAppUUID:(NSString *)hashedUUID
{
    [self archiveObject:hashedUUID forKey:k_appHashedUUIDKeyName];
}



+ (void)saveToLockbox:(NSString *)value forUsername:(NSString *)username keyName:(NSString *)keyName
{
    @synchronized(self) // thread safety support
    {
        // DDLogInfo(@"%@: saveToLockbox:\"%@\" forUsername:\"%@\" keyName:\"%@\"", THIS_FILE, value, username, keyName);

        NSDictionary *allUserAccountDict = [self unarchiveObjectForKey:k_userAccountInfoKey];
        if (allUserAccountDict)
        {
            NSString *hashUsername = [allUserAccountDict objectForKey:username];
            if (hashUsername)
            {
                /*Found it*/
                NSMutableDictionary *mutaUserDict = [[self unarchiveObjectForKey:hashUsername] mutableCopy];

                if (mutaUserDict)
                {
                    [mutaUserDict setObject:value forKey:keyName];
                    [Lockbox archiveObject:[NSDictionary dictionaryWithDictionary:mutaUserDict] forKey:hashUsername];
                }
                else
                {
                    DDLogWarn(@"%@:%@ - mutaUserDict is nil. We will not save %@ for %@ for user %@", THIS_FILE, THIS_METHOD, value, keyName, username);
                }
            }
            else
            {
                /*No record of it*/

                // Update userDict to include the new user's username
                NSString *hashUsername = [self hashForUsername:username];
                NSMutableDictionary *mutaAllUserAccountDict = [allUserAccountDict mutableCopy];
                [mutaAllUserAccountDict setObject:hashUsername forKey:username];
                [Lockbox archiveObject:[NSDictionary dictionaryWithDictionary:mutaAllUserAccountDict] forKey:k_userAccountInfoKey];

                // Create new dictionary and add object into user's own dict
                NSMutableDictionary *mutaUserDict = [[NSMutableDictionary alloc] init];
                if (mutaUserDict)
                {
                    [mutaUserDict setObject:value forKey:keyName];
                    [Lockbox archiveObject:[NSDictionary dictionaryWithDictionary:mutaUserDict] forKey:hashUsername];
                }
                else
                {
                    DDLogWarn(@"%@:%@ - mutaUserDict is nil. We will not save %@ for %@ for user %@", THIS_FILE, THIS_METHOD, value, keyName, username);
                }
            }
        }
        else
        {
            /*Does not exist*/
            // This is the actual dictionary that is storing the information
            NSString *hashUsername = [self hashForUsername:username];
            NSMutableDictionary *hashUsernameDict = [[NSMutableDictionary alloc] init];
            [hashUsernameDict setObject:hashUsername forKey:username];
            [Lockbox archiveObject:[NSDictionary dictionaryWithDictionary:hashUsernameDict] forKey:k_userAccountInfoKey];

            // This is the dictionary holding a mapping to all users
            NSMutableDictionary *userAccountDict = [[NSMutableDictionary alloc] init];
            [userAccountDict setObject:value forKey:keyName];

            [Lockbox archiveObject:[NSDictionary dictionaryWithDictionary:userAccountDict] forKey:hashUsername];
        }
    }
}



+ (NSString *)getLastUser
{
    return [self unarchiveObjectForKey:k_appLastUser];
}



+ (NSString *)getUserIdforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userIdKeyName];
}



+ (NSString *)getFirstNameforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_firstNameKeyName];
}



+ (NSString *)getLastNameforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_lastNameKeyName];
}



+ (NSString *)getFullNameforUsername:(NSString *)username
{
    NSString *firstName = [self readFromLockboxForUsername:username keyName:k_firstNameKeyName];
    NSString *lastName = [self readFromLockboxForUsername:username keyName:k_lastNameKeyName];

    return [NSString stringWithFormat:@"%@ %@", firstName, lastName];
}



+ (NSString *)getBadgeNumberForUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_badgeNumberKeyName];
}



+ (NSString *)getOrganizationNameforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_organizationNameKeyName];
}



+ (NSString *)getOrganizationStateforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_organizationStateKeyName];
}



+ (NSString *)getOrganizationCountryforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_organizationCountryKeyName];
}



+ (NSString *)getOrganizationCityforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_organizationCityKeyName];
}



+ (NSString *)getOrganizationAddressforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_organizationAddressKeyName];
}



+ (NSString *)getRealmEncryptionKeyforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userRealmEncryptionKeyName];
}



+ (NSString *)getUserFolderGUIDforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userFolderGUIDKeyName];
}



+ (NSString *)getUserHashPasswordforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userHashPasswordKeyName];
}



+ (NSString *)getUserFileEncryptionKeyforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userFileEncryptionKeyName];
}



+ (NSString *)getUserPasswordforUsername:(NSString *)username
{
    return [self readFromLockboxForUsername:username keyName:k_userPasswordKeyName];
}



+ (NSUInteger)getActiveUserCount
{
    return [self dictionaryForKey:k_userAccountInfoKey].count;
}



+ (NSString *)getHashedAppUUID
{
    return [self stringForKey:k_appHashedUUIDKeyName];
}



+ (NSString *)readFromLockboxForUsername:(NSString *)username keyName:(NSString *)keyName
{
    @synchronized (self)
    {
        NSDictionary *allUserAccountDict = [self unarchiveObjectForKey:k_userAccountInfoKey];
        if (allUserAccountDict)
        {
            NSString *hashedUsername = [allUserAccountDict objectForKey:username];
            if (hashedUsername)
            {
                /*Found it*/
                NSDictionary *userAccountDict = [self unarchiveObjectForKey:hashedUsername];
                return [userAccountDict objectForKey:keyName];
            }
            else
            {
                /*No record of it*/
                return nil;
            }
        }
        else
        {
            /*Does not exist*/
            // This is the actual dictionary that is storing the information
            return nil;
        }
    }
}



+ (NSString *)hashForUsername:(NSString *)username
{
    NSString  *inStr = [NSString stringWithFormat:@"%@", username];

    unsigned char digest[CC_SHA1_DIGEST_LENGTH];

    NSData *stringBytes = [inStr dataUsingEncoding:NSUTF8StringEncoding];  // or some other encoding
    if (CC_SHA1([stringBytes bytes], (CC_LONG)[stringBytes length], digest))
    {
        // SHA-1 hash has been calculated and stored in 'digest'.
        NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

        for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        {
            [output appendFormat:@"%02x", digest[i]];
        }

        return output;
    }
    else
    {
        return nil;
    }
}



+ (void)cleanKeyChain
{
    NSDictionary *allUserAccountDict = [self dictionaryForKey:k_userAccountInfoKey];

    for (NSString *hashUsername in allUserAccountDict.allValues)
    {
        [Lockbox archiveObject:nil forKey:hashUsername];
    }

    [Lockbox archiveObject:nil forKey:k_userAccountInfoKey];
    [Lockbox archiveObject:nil forKey:k_appLastUser];
}



+ (void)dumpLockboxInfoForUsername:(NSString *)username
{
    DDLogInfo(@"%@:%@ \"%@\"", THIS_FILE, THIS_METHOD, username);

    NSDictionary *allUserAccountDict = [self unarchiveObjectForKey:k_userAccountInfoKey];
    if (allUserAccountDict)
    {
        NSString *hashedUsername = [allUserAccountDict objectForKey:username];
        if (hashedUsername)
        {
            /*Found it*/
            NSDictionary *userAccountDict = [self unarchiveObjectForKey:hashedUsername];

            DDLogInfo(@"%@:%@ Realm Encryption Key: \"%@\"", THIS_FILE, THIS_METHOD, [RealmController hexadecimalString:[RealmController convertUUIDTo64ByteKey:[userAccountDict objectForKey:k_userRealmEncryptionKeyName]]]);
            DDLogInfo(@"%@:%@ fileEncryptionKey = %@", THIS_FILE, THIS_METHOD, userAccountDict[@"fileEncryptionKey"]);
            DDLogInfo(@"%@:%@ userFolderGUID = %@", THIS_FILE, THIS_METHOD, userAccountDict[@"userFolderGUID"]);
            DDLogInfo(@"%@:%@ userHashPassword = %@", THIS_FILE, THIS_METHOD, userAccountDict[@"userHashPassword"]);
            DDLogInfo(@"%@:%@ userId = %@", THIS_FILE, THIS_METHOD, userAccountDict[@"userId"]);
        }
        else
        {
            /*No record of it*/
            DDLogError(@"%@:%@ - Unable to find Lockbox for username = %@", THIS_FILE, THIS_METHOD, username);
        }
    }
    else
    {
        /*Does not exist*/
        // This is the actual dictionary that is storing the information
        DDLogError(@"%@:%@ - Unable to find Lockbox for username = %@", THIS_FILE, THIS_METHOD, username);
    }
}



@end