#include "NativeShims.h"
#import <AppKit/AppKit.h>
#import <GameController/GameController.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>

extern const char *mb_present_clear(CAMetalLayer *, id<MTLCommandQueue>, CGSize, MTLClearColor);

double mb_main_display_scale() {
    if (![NSThread isMainThread])
        return 0;
    return [[NSScreen mainScreen] backingScaleFactor];
}
unsigned mb_connected_controllers() { return (unsigned)[[GCController controllers] count]; }

const char *mb_present_window() {
    if (![NSThread isMainThread])
        return "Window creation requires the main thread";
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        [app finishLaunching];
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device)
            return "Metal device unavailable";
        id<MTLCommandQueue> queue = [device newCommandQueue];
        NSWindow *window =
            [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 480, 270)
                                        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                  NSWindowStyleMaskResizable
                                          backing:NSBackingStoreBuffered
                                            defer:NO];
        window.releasedWhenClosed = NO;
        window.title = @"MetalBridge presentation check";
        CAMetalLayer *layer = [CAMetalLayer layer];
        layer.device = device;
        layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        NSView *view = window.contentView;
        view.wantsLayer = YES;
        view.layer = layer;
        [window center];
        [window makeKeyAndOrderFront:nil];
        [app activateIgnoringOtherApps:YES];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:2.0];
        const char *failure = nullptr;
        do {
            @autoreleasepool {
                NSEvent *event =
                    [app nextEventMatchingMask:NSEventMaskAny
                                     untilDate:[NSDate dateWithTimeIntervalSinceNow:1.0 / 60]
                                        inMode:NSDefaultRunLoopMode
                                       dequeue:YES];
                if (event)
                    [app sendEvent:event];
                if (!window.visible)
                    break;
                layer.contentsScale = window.backingScaleFactor;
                auto size = [view convertRectToBacking:view.bounds].size;
                float stick =
                    GCController.controllers.firstObject.extendedGamepad.leftThumbstick.xAxis.value;
                failure = mb_present_clear(layer, queue, size,
                                           MTLClearColorMake(0.15 + 0.1 * stick, 0.38, 0.75, 1));
            }
        } while (!failure && deadline.timeIntervalSinceNow > 0);
        [window close];
#if !__has_feature(objc_arc)
        [window release];
        [queue release];
        [device release];
#endif
        return failure;
    }
}
