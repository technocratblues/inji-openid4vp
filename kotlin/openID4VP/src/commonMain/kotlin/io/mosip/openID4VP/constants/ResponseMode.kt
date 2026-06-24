package io.mosip.openID4VP.constants

    enum class ResponseMode(val value: String) {
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),

    IAR_POST("iar-post"),
    IAR_POST_JWT("iar-post.jwt"),

    IAE_POST("iae_post"),
    IAE_POST_JWT("iae_post.jwt"),
}
