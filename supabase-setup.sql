-- ════════════════════════════════════════════════════════════════════════════
--  PICK UP! — SETUP SICUREZZA SUPABASE (Row Level Security + Admin)
--  Esegui questo script UNA VOLTA su: Supabase → SQL Editor → New Query → Run
--  È idempotente: puoi rieseguirlo senza problemi.
-- ════════════════════════════════════════════════════════════════════════════

-- ─── 1. ABILITA RLS SU TUTTE LE TABELLE ──────────────────────────────────────
alter table companies     enable row level security;
alter table drivers       enable row level security;
alter table users         enable row level security;
alter table trips         enable row level security;
alter table bookings      enable row level security;
alter table verifications enable row level security;
alter table messages      enable row level security;
alter table reviews       enable row level security;

-- ─── 2. RUOLO ADMIN (sicurezza VERA lato server) ─────────────────────────────
-- Il controllo ADMIN_EMAIL nell'HTML è solo estetico. La protezione reale è qui.
create table if not exists admins (
  auth_id uuid primary key references auth.users(id) on delete cascade
);
alter table admins enable row level security;

-- Funzione helper: true se l'utente loggato è admin.
create or replace function is_admin() returns boolean
  language sql security definer stable as $BODY$
    select exists(select 1 from admins where auth_id = auth.uid());
  $BODY$;



-- ─── 3. LETTURE PUBBLICHE (viaggi, aziende, autisti, recensioni) ─────────────
drop policy if exists "Viaggi pubblici"      on trips;
drop policy if exists "Aziende pubbliche"    on companies;
drop policy if exists "Autisti pubblici"     on drivers;
drop policy if exists "Recensioni pubbliche" on reviews;
create policy "Viaggi pubblici"      on trips     for select using (true);
create policy "Aziende pubbliche"    on companies for select using (true);
create policy "Autisti pubblici"     on drivers   for select using (true);
create policy "Recensioni pubbliche" on reviews   for select using (true);

-- ─── 4. AZIENDE: chiunque può crearne di nuove (dalla registrazione autista) ─
drop policy if exists "Inserisci azienda" on companies;
create policy "Inserisci azienda" on companies for insert with check (true);

-- ─── 5. VIAGGI: l'autista gestisce solo i propri ────────────────────────────
drop policy if exists "Autista gestisce propri viaggi" on trips;
create policy "Autista gestisce propri viaggi" on trips
  for all using (driver_id in (select id from drivers where auth_id = auth.uid()));

-- ─── 6. PRENOTAZIONI: l'utente vede e crea solo le proprie ──────────────────
drop policy if exists "Utente vede proprie prenotazioni" on bookings;
drop policy if exists "Utente crea prenotazioni"         on bookings;
create policy "Utente vede proprie prenotazioni" on bookings
  for select using (user_id = auth.uid());
create policy "Utente crea prenotazioni" on bookings
  for insert with check (user_id = auth.uid());

-- ─── 7. PROFILI: ognuno gestisce il proprio ─────────────────────────────────
drop policy if exists "Utente gestisce profilo"  on users;
drop policy if exists "Autista gestisce profilo" on drivers;
create policy "Utente gestisce profilo" on users
  for all using (id = auth.uid());
create policy "Autista gestisce profilo" on drivers
  for all using (auth_id = auth.uid());
-- ⚠️ NOTA: questa policy lascia l'autista libero di modificare anche il proprio
-- 'rating'. Vedi il punto 11 in fondo per bloccarlo in modo pulito.

-- ─── 8. RECENSIONI: le scrive solo il passeggero autenticato ────────────────
drop policy if exists "Utente scrive recensione" on reviews;
create policy "Utente scrive recensione" on reviews
  for insert with check (user_id = auth.uid());

-- ─── 9. CHAT: solo le due parti della prenotazione ──────────────────────────
drop policy if exists "Chat solo parti coinvolte" on messages;
drop policy if exists "Chat invio messaggi"       on messages;
create policy "Chat solo parti coinvolte" on messages
  for select using (
    booking_id in (
      select b.id from bookings b
      join trips t   on t.id = b.trip_id
      join drivers d on d.id = t.driver_id
      where b.user_id = auth.uid() or d.auth_id = auth.uid()
    )
  );
-- NB: l'app salva sender_id = auth.uid() sia per il passeggero (users.id)
-- sia per l'autista (drivers.auth_id). Quindi il check è unico e semplice.
create policy "Chat invio messaggi" on messages
  for insert with check (sender_id = auth.uid());

-- ─── 10. VERIFICHE IDENTITÀ ──────────────────────────────────────────────────
-- L'autista crea/vede solo la propria; l'ADMIN legge e aggiorna tutto.
drop policy if exists "Autista crea verifica"       on verifications;
drop policy if exists "Autista vede propria verifica" on verifications;
drop policy if exists "Admin legge verifiche"       on verifications;
drop policy if exists "Admin aggiorna verifiche"    on verifications;
drop policy if exists "Admin aggiorna stato autisti" on drivers;
create policy "Autista crea verifica" on verifications
  for insert with check (
    driver_id in (select id from drivers where auth_id = auth.uid())
  );
create policy "Autista vede propria verifica" on verifications
  for select using (
    driver_id in (select id from drivers where auth_id = auth.uid())
    or is_admin()
  );
create policy "Admin aggiorna verifiche" on verifications
  for update using (is_admin());
-- L'admin deve poter marcare l'autista come verificato:
create policy "Admin aggiorna stato autisti" on drivers
  for update using (is_admin());

-- ─── 11. Blocca l'auto-modifica di rating/verifica da parte dell'autista ────
-- L'autista non può cambiarsi rating né auto-verificarsi. Il rating è scritto
-- SOLO dal trigger di ricalcolo (punto 13), riconosciuto tramite un flag.
create or replace function lock_driver_rating() returns trigger
  language plpgsql security definer as $BODY$
  begin
    if not is_admin() then
      -- il rating può cambiarlo solo il trigger di ricalcolo recensioni
      if current_setting('pickup.rating_recalc', true) is distinct from '1' then
        new.rating := old.rating;
      end if;
      new.verified := old.verified;  -- non ci si auto-verifica
      -- l'autista può solo RICHIEDERE la verifica (impostare 'pending'),
      -- non può passare a 'verified'/'rejected' da solo.
      if new.verification_status is distinct from old.verification_status
         and new.verification_status <> 'pending' then
        new.verification_status := old.verification_status;
      end if;
    end if;
    return new;
  end;
  $BODY$;
drop trigger if exists trg_lock_driver_rating on drivers;
create trigger trg_lock_driver_rating
  before update on drivers
  for each row execute function lock_driver_rating();

-- ─── 12. DATI DI CONTATTO DEL PASSEGGERO sulla prenotazione ─────────────────
-- Telefono, nota per l'autista e nomi degli altri passeggeri (prassi ridesharing).
alter table bookings
  add column if not exists passenger_phone text,
  add column if not exists passenger_note  text,
  add column if not exists passenger_names jsonb default '[]'::jsonb;

-- ─── 13. RICALCOLO AUTOMATICO DEL RATING AUTISTA dalle recensioni ───────────
-- Gira lato server (security definer): funziona anche con RLS attivo, senza
-- che il passeggero abbia il permesso di scrivere sulla tabella drivers.
create or replace function recalc_driver_rating() returns trigger
  language plpgsql security definer as $BODY$
  declare v_driver uuid; v_avg numeric;
  begin
    v_driver := coalesce(new.driver_id, old.driver_id);
    select round(avg(rating)::numeric, 1) into v_avg from reviews where driver_id = v_driver;
    perform set_config('pickup.rating_recalc', '1', true);  -- sblocca il lock del punto 11
    update drivers set rating = coalesce(v_avg, 5.0) where id = v_driver;
    return null;
  end;
  $BODY$;
drop trigger if exists trg_recalc_rating on reviews;
create trigger trg_recalc_rating
  after insert or update or delete on reviews
  for each row execute function recalc_driver_rating();

-- ─── 14. CHAT IN TEMPO REALE: abilita il Realtime sulla tabella messages ────
-- Senza questo la chat si aggiorna solo ricaricando la pagina.
do $BODY$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='messages'
  ) then
    alter publication supabase_realtime add table messages;
  end if;
end $BODY$;

-- ════════════════════════════════════════════════════════════════════════════
--  FATTO. Ricorda di aver inserito il tuo auth_id nella tabella admins (punto 2).
-- ════════════════════════════════════════════════════════════════════════════
