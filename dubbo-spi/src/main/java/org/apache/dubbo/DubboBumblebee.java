package org.apache.dubbo;

import org.apache.dubbo.config.annotation.Service;

public class DubboBumblebee implements DubboRoto{
    @Override
    public void sayHello() {
        System.out.println("Hello, I am DubboBumblebee.");
    }
}
