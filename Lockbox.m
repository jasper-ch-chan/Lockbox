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
#define k_userFolderGUIDKeyName @"userFolderGUID"
#define k_userCoreDataEncryptionKeyName @"coreDataEncryptionKey"
#define k_userFileEncryptionKey @"fileEncryptionKey"
#define k_userHashPassword @"userHashPassword"

static Lockbox *_lockBox = nil;
static NSString *_defaultKeyPrefix = nil;

@interface Lockbox ()
@property (strong, nonatomic, readwrite) NSString *keyPrefix;
@end

@interface UserAccountInfo : NSDictionary
@property (nonatomic, copy) NSString *userId;
@property (nonatomic, copy) NSString *userFolderGUID;
@property (nonatomic, copy) NSString *userCoreDataEncryptionKey;
@property (nonatomic, copy) NSString *userFileEncryptionKey;
@property (nonatomic, copy) NSString *userHashPassword;
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
    OSStatus status;

    NSString *hierKey = [self _hierarchicalKey:key];

    // If the object is nil, delete the item
    if (!obj)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        status = SecItemDelete((LOCKBOX_DICTREF)query);
        return (status == errSecSuccess);
    }

    NSMutableDictionary *dict = [self _service];
    [dict setObject:hierKey forKey:(LOCKBOX_ID) kSecAttrService];
    [dict setObject:(LOCKBOX_ID)(accessibility) forKey:(LOCKBOX_ID) kSecAttrAccessible];
    [dict setObject:[obj dataUsingEncoding:NSUTF8StringEncoding] forKey:(LOCKBOX_ID) kSecValueData];

    status = SecItemAdd ((LOCKBOX_DICTREF) dict, NULL);
    if (status == errSecDuplicateItem)
    {
        NSMutableDictionary *query = [self _query];
        [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];
        status = SecItemDelete((LOCKBOX_DICTREF)query);
        if (status == errSecSuccess)
        {
            status = SecItemAdd((LOCKBOX_DICTREF) dict, NULL);
        }
    }

    if (status != errSecSuccess)
    {
        DLog(@"SecItemAdd failed for key %@: %d", hierKey, (int)status);
    }

    return (status == errSecSuccess);
}



- (NSString *)objectForKey:(NSString *)key
{
    NSString *hierKey = [self _hierarchicalKey:key];

    NSMutableDictionary *query = [self _query];
    [query setObject:hierKey forKey:(LOCKBOX_ID)kSecAttrService];

    CFDataRef data = nil;
    OSStatus status =
        SecItemCopyMatching ( (LOCKBOX_DICTREF) query, (CFTypeRef *) &data );
    if (status != errSecSuccess && status != errSecItemNotFound)
    {
        DLog(@"SecItemCopyMatching failed for key %@: %d", hierKey, (int)status);
    }

    if (!data)
    {
        return nil;
    }

    NSString *s = [[NSString alloc] initWithData:(__bridge_transfer NSData *)data encoding:NSUTF8StringEncoding];

    return s;
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



#pragma mark self added in code for ze projects

+ (void)saveUserId:(NSString *)userId forUsername:(NSString *)username
{
    [self saveToLockbox:userId forUsername:username keyName:k_userIdKeyName];
}



+ (void)saveCoreDataEncryptionKey:(NSString *)encryptionKey forUsername:(NSString *)username
{
    [self saveToLockbox:encryptionKey forUsername:username keyName:k_userCoreDataEncryptionKeyName];
}



+ (void)saveUserFolderGUID:(NSString *)folderGUID forUsername:(NSString *)username
{
    [self saveToLockbox:folderGUID forUsername:username keyName:k_userFolderGUIDKeyName];
}



+ (void)saveUserHashPassword:(NSString *)hashPassword forUsername:(NSString *)username
{
    [self saveToLockbox:hashPassword forUsername:username keyName:k_userHashPassword];
}



+ (void)saveUserFileEncryptionKey:(NSString *)encryptionKey forUsername:(NSString *)username
{
    [self saveToLockbox:encryptionKey forUsername:username keyName:k_userFileEncryptionKey];
}



+ (void)saveToLockbox:(NSString *)value forUsername:(NSString *)username keyName:(NSString *)keyName
{
    NSDictionary *allUserAccountDict = [self dictionaryForKey:k_userAccountInfoKey];
    if (allUserAccountDict)
    {
        NSDictionary *userInfoDict = [allUserAccountDict objectForKey:username];
        if (userInfoDict)
        {
            /*Found it*/
            NSMutableDictionary *userInfo = [userInfoDict mutableCopy];
            [userInfo setObject:value forKey:keyName];

            NSMutableDictionary *mutaAllUserAccountDict = [allUserAccountDict mutableCopy];
            [mutaAllUserAccountDict setObject:[NSDictionary dictionaryWithDictionary:userInfo] forKey:username];

            [Lockbox setDictionary:[NSDictionary dictionaryWithDictionary:mutaAllUserAccountDict] forKey:k_userAccountInfoKey];
        }
        else
        {
            /*No record of it*/
            NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] init];
            [userInfo setObject:value forKey:keyName];

            NSMutableDictionary *mutaAllUserAccountDict = [allUserAccountDict mutableCopy];
            [mutaAllUserAccountDict setObject:[NSDictionary dictionaryWithDictionary:userInfo] forKey:username];

            [Lockbox setDictionary:[NSDictionary dictionaryWithDictionary:mutaAllUserAccountDict] forKey:k_userAccountInfoKey];
        }
    }
    else
    {
        /*Does not exist*/
        // This is the actual dictionary that is storing the information
        NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] init];
        [userInfo setObject:value forKey:keyName];

        // This is the dictionary holding a mapping to all users
        NSMutableDictionary *mutaAllUserAccountDict = [allUserAccountDict mutableCopy];
        [mutaAllUserAccountDict setObject:[NSDictionary dictionaryWithDictionary:userInfo] forKey:username];
        [Lockbox setDictionary:[NSDictionary dictionaryWithDictionary:mutaAllUserAccountDict] forKey:k_userAccountInfoKey];
    }
}



+ (void)getUserIdforUsername:(NSString *)username
{
    [self readFromLockboxForUsername:username keyName:k_userIdKeyName];
}



+ (void)getCoreDataEncryptionKeyforUsername:(NSString *)username
{
    [self readFromLockboxForUsername:username keyName:k_userCoreDataEncryptionKeyName];
}



+ (void)getUserFolderGUIDforUsername:(NSString *)username
{
    [self readFromLockboxForUsername:username keyName:k_userFolderGUIDKeyName];
}



+ (void)getUserHashPasswordforUsername:(NSString *)username
{
    [self readFromLockboxForUsername:username keyName:k_userHashPassword];
}



+ (void)getUserFileEncryptionKeyforUsername:(NSString *)username
{
    [self readFromLockboxForUsername:username keyName:k_userFileEncryptionKey];
}



+ (NSString *)readFromLockboxForUsername:(NSString *)username keyName:(NSString *)keyName
{
    NSDictionary *allUserAccountDict = [self dictionaryForKey:k_userAccountInfoKey];
    if (allUserAccountDict)
    {
        NSDictionary *userInfoDict = [allUserAccountDict objectForKey:username];
        if (userInfoDict)
        {
            /*Found it*/
            return [userInfoDict objectForKey:keyName];
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



+ (NSString *)encryptionKeyForUser:(NSString*)userName forKey:(NSString *)key
{
    NSDictionary*encryptionKeyDict = [self dictionaryForKey:key];
    return [encryptionKeyDict objectForKey:userName];
}



@end