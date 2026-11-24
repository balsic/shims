#include "NativeShims.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>

// Shared by the Cocoa window path. Resize using physical pixels on every
// present so that moving between displays uses the view's current scale.
const char *mb_present_clear(CAMetalLayer *layer, id<MTLCommandQueue> queue, CGSize pixels,
                             MTLClearColor color) {
    if (!queue || pixels.width < 1 || pixels.height < 1)
        return "Missing Metal queue or drawable area";
    layer.drawableSize = pixels;
    id<CAMetalDrawable> drawable = [layer nextDrawable];
    if (!drawable)
        return "CAMetalLayer has no drawable";
    MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
    pass.colorAttachments[0].texture = drawable.texture;
    pass.colorAttachments[0].loadAction = MTLLoadActionClear;
    pass.colorAttachments[0].storeAction = MTLStoreActionStore;
    pass.colorAttachments[0].clearColor = color;
    id<MTLCommandBuffer> commands = [queue commandBuffer];
    id<MTLRenderCommandEncoder> encoder = [commands renderCommandEncoderWithDescriptor:pass];
    if (!encoder)
        return "Cannot create Metal render pass";
    [encoder endEncoding];
    [commands presentDrawable:drawable];
    [commands commit];
    [commands waitUntilCompleted];
    return commands.status == MTLCommandBufferStatusCompleted ? nullptr : "Metal command buffer failed";
}

bool mb_metal3_available() {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        return device && [device supportsFamily:MTLGPUFamilyMetal3];
    }
}
bool mb_metal4_available() {
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (@available(macOS 26, *)) {
        @autoreleasepool {
            return [MTLCreateSystemDefaultDevice() supportsFamily:MTLGPUFamilyMetal4];
        }
    }
#endif
    return false;
}
