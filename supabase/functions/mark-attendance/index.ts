import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.7.1"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Replaces Utilities.computeDigest from Google Apps Script
async function generateLocalHash(message: string) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { scannedData, user, token, offlineDate, offlineTime, localHash } = await req.json()

    // 1. Cryptographic Tamper Check for Offline Scans
    if (offlineDate && offlineTime) {
      if (!localHash) throw new Error("SECURITY REJECT: Missing signature.");
      const expectedHash = await generateLocalHash(String(scannedData) + String(offlineTime) + String(token));
      if (localHash !== expectedHash) throw new Error("SECURITY REJECT: Payload tampered.");
    }

    // Connect to Supabase using the invoker's JWT to respect RLS
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: req.headers.get('Authorization')! } } }
    )

    // 2. Identify Cadet (Stripping leading zeros safely as patched in Phase 0)
    const cleanId = String(scannedData).replace(/^[=+\-@\t\r]/, "").trim().replace(/^0+/, '');
    if (!cleanId) throw new Error("Invalid QR code format.");

    const { data: cadet, error: cadetErr } = await supabase
      .from('cadets')
      .select('*')
      .eq('id', cleanId)
      .single();
    
    if (cadetErr || !cadet) throw new Error("UNAUTHORIZED QR: Cadet not found.");
    
    const matchedId = cadet.id;
    const studentName = `${cadet.first_name} ${cadet.middle_name ? cadet.middle_name + ' ' : ''}${cadet.last_name}`;

    // 3. Time calculations mapped to Manila Time (UTC+8)
    const now = new Date();
    const formatterDate = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Manila', month: '2-digit', day: '2-digit', year: 'numeric' });
    const formatterTime = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Manila', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    
    const todayDate = offlineDate || formatterDate.format(now);
    const timestamp = offlineTime || formatterTime.format(now);
    
    let currentHour = 0;
    let currentMin = 0;
    
    if (offlineTime) {
        const timeParts = offlineTime.split(/:| /);
        currentHour = parseInt(timeParts[0], 10);
        currentMin = parseInt(timeParts[1], 10);
        if (timeParts[3] === "PM" && currentHour !== 12) currentHour += 12;
        if (timeParts[3] === "AM" && currentHour === 12) currentHour = 0;
    } else {
        const phTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Manila' }));
        currentHour = phTime.getHours();
        currentMin = phTime.getMinutes();
    }

    // 4. Validate against Training Schedule
    const { data: scheduleData } = await supabase.from('training_schedule').select('*').eq('date', todayDate).single();
    if (!scheduleData) throw new Error("NO TRAINING SCHEDULED FOR TODAY.");

    let activeDbDate = todayDate;
    let isAM = false;

    if (scheduleData.type === "Double" || scheduleData.type === "Double (AM & PM)") {
        if (currentHour < 12) {
            activeDbDate += " - AM";
            isAM = true;
        } else {
            activeDbDate += " - PM";
            isAM = false;
        }
    }

    // Calculate arrival status based on existing rules
    let arrivalStatus = "Present";
    if (isAM) {
        if (currentHour < 7 || (currentHour === 7 && currentMin === 0)) arrivalStatus = "Present";
        else if (currentHour === 7 && currentMin >= 1 && currentMin <= 15) arrivalStatus = "Late";
        else arrivalStatus = "Very Late";
    } else {
        if (currentHour < 13 || (currentHour === 13 && currentMin === 0)) arrivalStatus = "Present";
        else if (currentHour === 13 && currentMin >= 1 && currentMin <= 15) arrivalStatus = "Late";
        else arrivalStatus = "Very Late";
    }

    // 5. Transactional Insert / Update (Replaces LockService)
    const { data: insertData, error: insertError } = await supabase
      .from('attendance')
      .insert([{
        cadet_id: matchedId,
        session_date: activeDbDate,
        time_in: timestamp,
        status: arrivalStatus
      }]);

    if (insertError) {
      // 23505 is the Postgres code for Unique Violation (meaning they already timed in)
      if (insertError.code === '23505') {
         const { data: existingRec } = await supabase
            .from('attendance')
            .select('*')
            .eq('cadet_id', matchedId)
            .eq('session_date', activeDbDate)
            .single();
            
         if (existingRec.time_out) {
            return new Response(JSON.stringify({ status: "warn", msg: "Already completed Time In & Out for this session!", name: studentName }), { headers: corsHeaders });
         } else {
            // Execute Time Out
            await supabase.from('attendance').update({ time_out: timestamp }).eq('id', existingRec.id);
            return new Response(JSON.stringify({ 
              msg: "TIME OUT Recorded!", status: "ok", id: matchedId, name: studentName, 
              image: cadet.image_url, timeIn: existingRec.time_in, timeOut: timestamp, 
              date: activeDbDate, action: "TIME OUT" 
            }), { headers: corsHeaders });
         }
      } else {
         throw insertError;
      }
    }

    // Success on fresh Time In
    return new Response(JSON.stringify({ 
      msg: "TIME IN Recorded!", status: "ok", id: matchedId, name: studentName, 
      image: cadet.image_url, timeIn: timestamp, timeOut: "---", 
      date: activeDbDate, action: arrivalStatus.toUpperCase() 
    }), { headers: corsHeaders });

  } catch (err: any) {
    return new Response(JSON.stringify({ status: "warn", msg: err.message }), { headers: corsHeaders, status: 400 })
  }
})