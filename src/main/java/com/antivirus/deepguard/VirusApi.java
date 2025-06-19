package com.antivirus.deepguard;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;

import java.util.List;
import java.util.Map;

public interface VirusApi {
    @POST("/api/check_hash")
    Call<Map<String, Object>> checkHash(@Body Map<String, String> hashData);

    @GET("/api/get_signatures")
    Call<List<String>> getSignatures();

    @POST("/api/report_infection")
    Call<Map<String, String>> reportInfection(@Body Map<String, String> infectionData);
}
