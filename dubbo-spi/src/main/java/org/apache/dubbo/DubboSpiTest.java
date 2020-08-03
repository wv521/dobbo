package org.apache.dubbo;

import org.apache.dubbo.common.extension.ExtensionLoader;

public class DubboSpiTest {

    public static void main(String[] args) {

        ExtensionLoader<DubboRoto> extensionLoader = ExtensionLoader.getExtensionLoader(DubboRoto.class);
        DubboRoto optimusPrime = extensionLoader.getExtension("optimusPrime");
        optimusPrime.sayHello();

    }
}
