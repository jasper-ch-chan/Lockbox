//
// Lockbox.h
//
// Created by Mark H. Granoff on 4/19/12.
// Copyright (c) 2012 Hawk iMedia. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

@interface Lockbox : NSObject

#ifdef DEBUG
// For unit tests
@property (strong, nonatomic, readonly) NSString *keyPrefix;
#endif

@property (assign, nonatomic, readonly) OSStatus lastStatus;

// When the default key prefix (your app's bundle id) is not sufficient, instantiate your own
// instance of Lockbox specifying your own key prefix, and use the appropriate instance methods
// to store and retrieve keychain data. You can also instantiate your own instance and use the
// default key prefix simply by calling [[Lockbox alloc] init];
- (instancetype)initWithKeyPrefix:(NSString *)keyPrefix;

// When adding instance methods, remember to add a corresponding class method.

- (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key;
- (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key accessibility:(CFTypeRef)accessibility;

- (id)unarchiveObjectForKey:(NSString *)key;

- (BOOL)setString:(NSString *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:");
- (BOOL)setString:(NSString *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:accesibility");
- (NSString *)stringForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -unarchiveObject:forKey:");

- (BOOL)setArray:(NSArray *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:");
- (BOOL)setArray:(NSArray *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to archiveObject:forKey:accesibility");
- (NSArray *)arrayForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -unarchiveObject:forKey:");

- (BOOL)setSet:(NSSet *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:");
- (BOOL)setSet:(NSSet *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:accesibility");
- (NSSet *)setForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -unarchiveObject:forKey:");

- (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:");
- (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:accesibility");
- (NSDictionary *)dictionaryForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -unarchiveObject:forKey:");

- (BOOL)setDate:(NSDate *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:");
- (BOOL)setDate:(NSDate *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to -archiveObject:forKey:accesibility");
- (NSDate *)dateForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to -unarchiveObject:forKey:");

// Class methods that maintain the convenience of storing and retrieving data from the keychain
// using class-level methods. An internal instance of Lockbox is instantiated for the class that
// uses the instance methods above, and a key prefix equal to your app's bundle id.

+ (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key;
+ (BOOL)archiveObject:(id<NSSecureCoding>)object forKey:(NSString *)key accessibility:(CFTypeRef)accessibility;

+ (id)unarchiveObjectForKey:(NSString *)key;

+ (BOOL)setString:(NSString *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:");
+ (BOOL)setString:(NSString *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:accesibility");
+ (NSString *)stringForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +unarchiveObject:forKey:");

+ (BOOL)setArray:(NSArray *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:");
+ (BOOL)setArray:(NSArray *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:accesibility");
+ (NSArray *)arrayForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +unarchiveObject:forKey:");

+ (BOOL)setSet:(NSSet *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:");
+ (BOOL)setSet:(NSSet *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:accesibility");
+ (NSSet *)setForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +unarchiveObject:forKey:");

+ (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:");
+ (BOOL)setDictionary:(NSDictionary *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:accesibility");
+ (NSDictionary *)dictionaryForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +unarchiveObject:forKey:");

+ (BOOL)setDate:(NSDate *)value forKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:");
+ (BOOL)setDate:(NSDate *)value forKey:(NSString *)key accessibility:(CFTypeRef)accessibility DEPRECATED_MSG_ATTRIBUTE("Migrate to +archiveObject:forKey:accesibility");
+ (NSDate *)dateForKey:(NSString *)key DEPRECATED_MSG_ATTRIBUTE("Migrate to +unarchiveObject:forKey:");

// Save to Lockbox
+ (void)saveLastUser:(NSString *)lastUser;
+ (void)saveUserId:(NSString *)userId forUsername:(NSString *)username;
+ (void)saveFirstName:(NSString *)firstName forUsername:(NSString *)username;
+ (void)saveLastName:(NSString *)lastName forUsername:(NSString *)username;
+ (void)saveBadgeNumber:(NSString *)badgeNumber forUsername:(NSString *)username;
+ (void)saveOrganizationName:(NSString *)organizationName forUsername:(NSString *)username;
+ (void)saveOrganizationState:(NSString *)organizationState forUsername:(NSString *)username;
+ (void)saveOrganizationCountry:(NSString *)organizationCountry forUsername:(NSString *)username;
+ (void)saveOrganizationCity:(NSString *)organizationCity forUsername:(NSString *)username;
+ (void)saveOrganizationAddress:(NSString *)organizationAddress forUsername:(NSString *)username;
+ (void)saveRealmEncryptionKey:(NSData *)encryptionKey forUsername:(NSString *)username;
+ (void)saveUserFolderGUID:(NSString *)folderGUID forUsername:(NSString *)username;
+ (void)saveUserHashPassword:(NSString *)hashPassword forUsername:(NSString *)username;
+ (void)saveUserFileEncryptionKey:(NSString *)encryptionKey forUsername:(NSString *)username;
+ (void)saveUserPassword:(NSString *)userPassword forUsername:(NSString *)username;
+ (void)saveHashedAppUUID:(NSString *)hashedUUID;

// Get from Lockbox
+ (NSString *)getLastUser;
+ (NSString *)getUserIdforUsername:(NSString *)username;
+ (NSString *)getFirstNameforUsername:(NSString *)username;
+ (NSString *)getLastNameforUsername:(NSString *)username;
+ (NSString *)getFullNameforUsername:(NSString *)username;
+ (NSString *)getBadgeNumberForUsername:(NSString *)username;
+ (NSString *)getOrganizationNameforUsername:(NSString *)username;
+ (NSString *)getOrganizationStateforUsername:(NSString *)username;
+ (NSString *)getOrganizationCountryforUsername:(NSString *)username;
+ (NSString *)getOrganizationCityforUsername:(NSString *)username;
+ (NSString *)getOrganizationAddressforUsername:(NSString *)username;
+ (NSData *)getRealmEncryptionKeyforUsername:(NSString *)username;
+ (NSString *)getUserFolderGUIDforUsername:(NSString *)username;
+ (NSString *)getUserHashPasswordforUsername:(NSString *)username;
+ (NSString *)getUserFileEncryptionKeyforUsername:(NSString *)username;
+ (NSString *)getUserPasswordforUsername:(NSString *)username;
+ (NSUInteger)getActiveUserCount;
+ (NSString *)getHashedAppUUID;

// Clean Lockbox
+ (void)cleanKeyChain;

// Logging Lockbox support
+ (void)dumpLockboxInfoForUsername:(NSString *)username;

@end