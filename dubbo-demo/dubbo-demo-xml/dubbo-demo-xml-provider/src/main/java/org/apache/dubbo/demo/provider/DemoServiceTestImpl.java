package org.apache.dubbo.demo.provider;

import org.apache.dubbo.demo.DemoServiceTest;

public class DemoServiceTestImpl implements DemoServiceTest{
    @Override
    public String helloTest(String name) {
        return "say:"+ name;
    }
}
