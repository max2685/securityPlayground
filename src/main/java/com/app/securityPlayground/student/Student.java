package com.app.securityPlayground.student;

import lombok.Data;

@Data
public class Student {
    private final Integer studentId;
    private final String studentName;

    @Override
    public String toString() {
        return "Student{" +
                "studentId=" + studentId +
                ", studentName='" + studentName + '\'' +
                '}';
    }
}
