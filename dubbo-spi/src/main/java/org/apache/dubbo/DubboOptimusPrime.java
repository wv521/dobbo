package org.apache.dubbo;

import org.apache.dubbo.config.annotation.Service;

public class DubboOptimusPrime implements DubboRoto{
    @Override
    public void sayHello() {
        System.out.println("Hello, I am DubboOptimus Prime.");
    }
}
