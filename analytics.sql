-- Execute as the owner of the tables. Provision a separate datalens_reader login first.
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE OR REPLACE VIEW analytics.rental_daily AS
SELECT r.day, m.kind, r.status, count(*) AS orders,
       sum(r.hours) AS rental_hours, sum(r.km) AS distance_one_way,
       sum(r.delivery) AS delivery_sum, sum(r.total) AS quote_sum
FROM public.rental r JOIN public.machine m ON m.id = r.machine_id
GROUP BY r.day, m.kind, r.status;
REVOKE ALL ON SCHEMA analytics FROM PUBLIC;
GRANT USAGE ON SCHEMA analytics TO datalens_reader;
GRANT SELECT ON analytics.rental_daily TO datalens_reader;
