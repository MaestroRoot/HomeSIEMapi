--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: payment_channel; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.payment_channel AS ENUM (
    'yas_mix',
    'mpesa',
    'halopesa',
    'airtel_money',
    'card'
);


--
-- Name: payment_method; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.payment_method AS ENUM (
    'mobile_money',
    'bank_card'
);


--
-- Name: payment_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.payment_status AS ENUM (
    'pending',
    'processing',
    'succeeded',
    'failed',
    'cancelled'
);


--
-- Name: plan; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.plan AS ENUM (
    'Free',
    'Home',
    'Pro',
    'Business'
);


--
-- Name: subscription_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.subscription_status AS ENUM (
    'active',
    'pending',
    'past_due',
    'cancelled'
);


--
-- Name: user_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_role AS ENUM (
    'owner',
    'analyst',
    'viewer'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    name character varying(120) NOT NULL,
    slug character varying(120) NOT NULL,
    plan public.plan NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payments (
    organization_id uuid NOT NULL,
    subscription_id uuid,
    initiated_by_id uuid,
    plan public.plan NOT NULL,
    amount_tzs integer NOT NULL,
    currency character varying(3) NOT NULL,
    method public.payment_method NOT NULL,
    channel public.payment_channel NOT NULL,
    status public.payment_status NOT NULL,
    msisdn character varying(20),
    card_last4 character varying(4),
    card_brand character varying(20),
    reference character varying(64) NOT NULL,
    provider_reference character varying(128),
    provider character varying(32) NOT NULL,
    failure_reason text,
    paid_at timestamp with time zone,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscriptions (
    organization_id uuid NOT NULL,
    plan public.plan NOT NULL,
    status public.subscription_status NOT NULL,
    price_tzs integer NOT NULL,
    currency character varying(3) NOT NULL,
    started_at timestamp with time zone,
    current_period_end timestamp with time zone,
    cancelled_at timestamp with time zone,
    auto_renew boolean NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    firebase_uid character varying(128) NOT NULL,
    email character varying(320) NOT NULL,
    name character varying(120) NOT NULL,
    avatar_url character varying(512),
    role public.user_role NOT NULL,
    plan public.plan NOT NULL,
    mfa_enabled boolean NOT NULL,
    email_verified boolean NOT NULL,
    is_active boolean NOT NULL,
    last_login_at timestamp with time zone,
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (id);


--
-- Name: subscriptions subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: ix_organizations_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_organizations_slug ON public.organizations USING btree (slug);


--
-- Name: ix_payments_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_payments_organization_id ON public.payments USING btree (organization_id);


--
-- Name: ix_payments_provider_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_payments_provider_reference ON public.payments USING btree (provider_reference);


--
-- Name: ix_payments_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_payments_reference ON public.payments USING btree (reference);


--
-- Name: ix_payments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_payments_status ON public.payments USING btree (status);


--
-- Name: ix_payments_subscription_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_payments_subscription_id ON public.payments USING btree (subscription_id);


--
-- Name: ix_subscriptions_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_subscriptions_organization_id ON public.subscriptions USING btree (organization_id);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_firebase_uid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_firebase_uid ON public.users USING btree (firebase_uid);


--
-- Name: ix_users_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_organization_id ON public.users USING btree (organization_id);


--
-- Name: payments payments_initiated_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_initiated_by_id_fkey FOREIGN KEY (initiated_by_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: payments payments_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: payments payments_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.subscriptions(id) ON DELETE SET NULL;


--
-- Name: subscriptions subscriptions_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: users users_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--
