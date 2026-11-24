#import <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    @autoreleasepool {
        NSDictionary *info = NSBundle.mainBundle.infoDictionary;
        NSString *host = info[@"MetalBridgeHost"], *target = info[@"MetalBridgeTarget"];
        NSString *prefix = info[@"MetalBridgeAppID"];
        if (![host isKindOfClass:NSString.class] || !host.isAbsolutePath ||
            ![target isKindOfClass:NSString.class] || !target.isAbsolutePath ||
            ![prefix isKindOfClass:NSString.class])
            return 64;
        execl(host.fileSystemRepresentation, host.fileSystemRepresentation, "open-target", "--app-id",
              prefix.UTF8String, "--", target.fileSystemRepresentation, (char *)NULL);
        perror("MetalBridge launcher");
        return 69;
    }
}
