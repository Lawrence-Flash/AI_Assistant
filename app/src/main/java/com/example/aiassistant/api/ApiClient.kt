package com.example.aiassistant.api

import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object ApiClient {
    // Make sure your phone is connected to the EXACT same Wi-Fi network as the PC (192.168.2.110)
    private const val BASE_URL = "http://192.168.2.110:5001/"

    // Increase timeout settings to 60 seconds (since AI scans take a long time)
    private val okHttpClient = OkHttpClient.Builder()
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    val instance: AiAssistantApi by lazy {
        val retrofit = Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient) // Attach the custom client here
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        retrofit.create(AiAssistantApi::class.java)
    }
}