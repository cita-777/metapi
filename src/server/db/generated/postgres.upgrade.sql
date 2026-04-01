ALTER TABLE "proxy_logs" ADD COLUMN "is_stream" BOOLEAN;
ALTER TABLE "proxy_logs" ADD COLUMN "first_byte_latency_ms" INTEGER;
