#include <substrate.h>
#import <Foundation/Foundation.h>

// If the compiler understands __arm64e__, assume it's paired with an SDK that has
// ptrauth.h. Otherwise, it'll probably error if we try to include it so don't.
#if __arm64e__
#include <ptrauth.h>
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

// Given a pointer to instructions, sign it so you can call it like a normal fptr.
static void *make_sym_callable(void *ptr) {
#if __arm64e__
    ptr = ptrauth_sign_unauthenticated(ptrauth_strip(ptr, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0);
#endif
    return ptr;
}

// Given a function pointer, strip the PAC so you can read the instructions.
static void *make_sym_readable(void *ptr) {
#if __arm64e__
    ptr = ptrauth_strip(ptr, ptrauth_key_function_pointer);
#endif
    return ptr;
}

#pragma clang diagnostic pop

#define LOG(fmt, ...) NSLog(@"[WebInspect] " fmt "\n", ##__VA_ARGS__)

typedef CFStringRef(sec_task_copy_id_t)(void *task, CFErrorRef _Nullable *error);
sec_task_copy_id_t *SecTaskCopySigningIdentifier = NULL;
// NSSet<NSString *> *expected = NULL; // 不知道为什么，如果使用全局的变量来保存，在入口初始化后地址内容会变化

CFTypeRef (*original_SecTaskCopyValueForEntitlement)(void *task, CFStringRef entitlement, CFErrorRef _Nullable *error);

CFTypeRef hooked_SecTaskCopyValueForEntitlement(void *task, CFStringRef entitlement, CFErrorRef _Nullable *error) {
  NSString *casted = (__bridge NSString *)entitlement;
  NSString *identifier = (__bridge NSString *)SecTaskCopySigningIdentifier(task, NULL);
  LOG("check entitlement: %@ for %@", casted, identifier);
  // 改成实时生成对象，而不是使用全局对象。
  // 全局对象在arm64e设备上初始化后地址内容会一直变化，原因未知
  NSSet<NSString *> *expected = [NSSet setWithObjects:
      @"com.apple.security.get-task-allow",
      @"com.apple.webinspector.allow",
      @"com.apple.private.webinspector.allow-remote-inspection",
      @"com.apple.private.webinspector.allow-carrier-remote-inspection",
      nil
  ];
  // LOG("expected entitlements %@ %p", [expected class], expected);
  if ([expected containsObject:casted]) {
    LOG("allow %@", identifier);
    return kCFBooleanTrue;
  }
  return original_SecTaskCopyValueForEntitlement(task, entitlement, error);
}

%ctor {
  LOG(@"loaded in %s (%d)", getprogname(), getpid());
  // 用这种方式初始化后，在 hooked_SecTaskCopyValueForEntitlement 使用时，虽然地址相同，但是内容（对象类型）一直变化
  // static dispatch_once_t onceToken;
  // dispatch_once(&onceToken, ^{
  //   expected = [NSSet setWithObjects:
  //     @"com.apple.security.get-task-allow",
  //     @"com.apple.webinspector.allow",
  //     @"com.apple.private.webinspector.allow-remote-inspection",
  //     @"com.apple.private.webinspector.allow-carrier-remote-inspection",
  //     nil
  //   ];
  //   LOG("init expected entitlements %@ %p", [expected class], expected);
  // });

  MSImageRef image = MSGetImageByName("/System/Library/Frameworks/Security.framework/Security");
  if (!image) {
    LOG("Security framework not found, it is impossible");
    return;
  }
  // 兼容 arm64e 架构的 PAC机制
  SecTaskCopySigningIdentifier = (sec_task_copy_id_t *)make_sym_callable(MSFindSymbol(image, "_SecTaskCopySigningIdentifier"));
  MSHookFunction(
    MSFindSymbol(image, "_SecTaskCopyValueForEntitlement"),
    (void *)hooked_SecTaskCopyValueForEntitlement,
    (void **)&original_SecTaskCopyValueForEntitlement
  );
}
