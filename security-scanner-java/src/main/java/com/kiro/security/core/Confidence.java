package com.kiro.security.core;

public enum Confidence {
    HIGH(1.0),
    MEDIUM(0.75),
    LOW(0.5);

    private final double weight;

    Confidence(double weight) {
        this.weight = weight;
    }

    public double getWeight() { return weight; }
}
