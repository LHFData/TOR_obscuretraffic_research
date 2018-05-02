#include "connection.h"
#include "traffic_obscure.h"
static void
run_connection_housekeeping(int i, time_t now)
{
  cell_t cell;
  connection_t *conn = smartlist_get(connection_array, i);
  const or_options_t *options = get_options();
  or_connection_t *or_conn;
  channel_t *chan = NULL;
  int have_any_circuits;
  int past_keepalive =
    now >= conn->timestamp_lastwritten + options->KeepalivePeriod;

  if (conn->outbuf && !connection_get_outbuf_len(conn) &&
      conn->type == CONN_TYPE_OR)
    TO_OR_CONN(conn)->timestamp_lastempty = now;

  if (conn->marked_for_close) {
    /* nothing to do here */
    return;
  }

  /* Expire any directory connections that haven't been active (sent
   * if a server or received if a client) for 5 min */
  if (conn->type == CONN_TYPE_DIR &&
      ((DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastwritten
            + options->TestingDirConnectionMaxStall < now) ||
       (!DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastread
            + options->TestingDirConnectionMaxStall < now))) {
    log_info(LD_DIR,"Expiring wedged directory conn (fd %d, purpose %d)",
             (int)conn->s, conn->purpose);
    /* This check is temporary; it's to let us know whether we should consider
     * parsing partial serverdesc responses. */
    if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        connection_get_inbuf_len(conn) >= 1024) {
      log_info(LD_DIR,"Trying to extract information from wedged server desc "
               "download.");
      connection_dir_reached_eof(TO_DIR_CONN(conn));
    } else {
      connection_mark_for_close(conn);
    }
    return;
  }

  if (!connection_speaks_cells(conn))
    return; /* we're all done here, the rest is just for OR conns */

  /* If we haven't written to an OR connection for a while, then either nuke
     the connection or send a keepalive, depending. */

  or_conn = TO_OR_CONN(conn);
  tor_assert(conn->outbuf);

  chan = TLS_CHAN_TO_BASE(or_conn->chan);
  tor_assert(chan);

  if (channel_num_circuits(chan) != 0) {
    have_any_circuits = 1;
    chan->timestamp_last_had_circuits = now;
  } else {
    have_any_circuits = 0;
  }

  if (channel_is_bad_for_new_circs(TLS_CHAN_TO_BASE(or_conn->chan)) &&
      ! have_any_circuits) {
    /* It's bad for new circuits, and has no unmarked circuits on it:
     * mark it now. */
    log_info(LD_OR,
             "Expiring non-used OR connection to fd %d (%s:%d) [Too old].",
             (int)conn->s, conn->address, conn->port);
    if (conn->state == OR_CONN_STATE_CONNECTING)
      connection_or_connect_failed(TO_OR_CONN(conn),
                                   END_OR_CONN_REASON_TIMEOUT,
                                   "Tor gave up on the connection");
    connection_or_close_normally(TO_OR_CONN(conn), 1);
  } else if (!connection_state_is_open(conn)) {
    if (past_keepalive) {
      /* We never managed to actually get this connection open and happy. */
      log_info(LD_OR,"Expiring non-open OR connection to fd %d (%s:%d).",
               (int)conn->s,conn->address, conn->port);
      connection_or_close_normally(TO_OR_CONN(conn), 0);
    }
  } else if (we_are_hibernating() &&
             ! have_any_circuits &&
             !connection_get_outbuf_len(conn)) {
    /* We're hibernating, there's no circuits, and nothing to flush.*/
    log_info(LD_OR,"Expiring non-used OR connection to fd %d (%s:%d) "
             "[Hibernating or exiting].",
             (int)conn->s,conn->address, conn->port);
    connection_or_close_normally(TO_OR_CONN(conn), 1);
  } else if (!have_any_circuits &&
             now - or_conn->idle_timeout >=
                                         chan->timestamp_last_had_circuits) {
    log_info(LD_OR,"Expiring non-used OR connection "U64_FORMAT" to fd %d "
             "(%s:%d) [no circuits for %d; timeout %d; %scanonical].",
             U64_PRINTF_ARG(chan->global_identifier),
             (int)conn->s, conn->address, conn->port,
             (int)(now - chan->timestamp_last_had_circuits),
             or_conn->idle_timeout,
             or_conn->is_canonical ? "" : "non");
    connection_or_close_normally(TO_OR_CONN(conn), 0);
  } else if (
      now >= or_conn->timestamp_lastempty + options->KeepalivePeriod*10 &&
      now >= conn->timestamp_lastwritten + options->KeepalivePeriod*10) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,
           "Expiring stuck OR connection to fd %d (%s:%d). (%d bytes to "
           "flush; %d seconds since last write)",
           (int)conn->s, conn->address, conn->port,
           (int)connection_get_outbuf_len(conn),
           (int)(now-conn->timestamp_lastwritten));
    connection_or_close_normally(TO_OR_CONN(conn), 0);
  } else if (past_keepalive && !connection_get_outbuf_len(conn)) {
    /* send a padding cell */
    log_fn(LOG_DEBUG,LD_OR,"Sending keepalive to (%s:%d)",
           conn->address, conn->port);
    memset(&cell,0,sizeof(cell_t));
    cell.command = CELL_PADDING;
    connection_or_write_cell_to_buf(&cell, or_conn);
  } else {
    obscure_strategy(chan);
  }
}
/*
  to specific the channel's obscure status ,we have to define a few parameters to add 
  into the channel_t structure.
  we gonna define it here,and put it into the channel.h file later.
  unsigned int obscure_callback
  unsigned int obscure_enabled
  
  the options should also be marked,whether the obsucre should be used.
*/
void obscure_disable_on_channel(channel_t* chan){
  chan->obscure_enabled=0
  obscure_send_disable_command(chan);
}
static obscure_descision_t obscure_strategy(channel_t * chan){

  /*  connection_t *conn_traversal=smartlist_get(connection_array,i);
    const or_options_t *options=get_options();
    or_connection_t *or_conn;
    channel_T *chan=NULL;
    int circuits_exist;
    int past_alivekeep=now>=conn->timestamp_lastwritten+options->KeepalivePeriod;
    if(conn->outbuf&&!connection_get_outbuf_len(conn)&&conn->type=CONN_TYPE_OR)
    //if it's true ,it means this OR conn is empty now
        TO_OR_CONN(conn)->timestamp_lastempty=now;
    if(conn->marked_for_close){
        return;
    }
    if(conn->type==CONN_TYPE_DIR&&((DIR_CONN_IS_SERVER(conn)&&
    conn->timestamp_lastwritten+options->TestingDirConnectionMaxStall<now)||
    (!DIR_CONN_IS_SERVER(conn)&&conn->timestamp_lastread+options->TestingDirConnectionMaxStall<now))){
        log()
    }*/
    const or_options_t *options=get_options();
    /*channel status check*/
    if(chan->state!=CHANNEL_STATE_OPEN)
      return obscure_none;
    if(chan->channel_usage!=CHANNEL_USED_FOR_USER_TRAFFIC)
      return obscure_none;
    if(chan->obscure_callback)
      return obscure_already_scheduled;
    if(!chan->obscure_enabled&&options->ConnectionObscure)
      return obscure_none;
    if(options->Tor2webMode){
      if(chan->obscure_enabled)
        obscure_disable_on_channel(chan);
      return obscure_none;
    }
    if(!chan->has_queued_writes(chan)){
      int is_client_channel=0;
      if(CHANNEL_IS_CLIENT(chan,options)){
        is_client_channel=1;
      }
      int 64_t obscure_time_ms=obscure_time_compute(chan);
      if(obscure_time_ms==OBSCURE_TIME_DISABLED){
        return obscure_none;
      }else if(obscure_time_ms==OBSCURE_TIME_LATER){
        chan->currently_obscure=1;
        return obscure_later;
      }else{
        chan->currently_obscure=1;
        return obscure_schedule(chan,(int)obscure_time_ms);
      }
    }else {
      return obscure_later;
    }
    
}
static void obscure_send_callback(tor_timer_t *timer,void *args,const struct monotime_t *when){
  channel_t *chan=channel_handle_get((struct channel_handle_t *)args);(void*)timer;(void)when;
  if(chan&&CHANNEL_CAN_HANDLE_CELLS(chan)){
    obscure_send_cell_for_callback(chan);
  }
  total_timers_pending--;
}
static obscure_descision_t obscure_schedule(channel_t * chan,int in_ms){
  struct timeval timeout;
  //no assert 
   if(in_ms<=0){
     chan->pending_obscure_callback=1;
     obscure_send_cell_for_callback(chan);
     return obscure_sent;
   }
   timeout.tv_sec=in_ms/TOR_MSEC_PER_SEC;
   timeout.tv_usec=(in_ms%TOR_USEC_PER_MSEC)*TOR_USEC_PER_MSEC;
   if(!chan->timer_handle){
     timer_set_cb(chan->obscure_timer,obscure_send_callback,chan->timer_handle);
   }else{
     chan->obscure_timer=timer_new(obscure_send_callback,chan->timer_handle);
   }
   timer_schedule(chan->obscure_timer,&timeout);
   rep_hist_padding_count_timers(++total_timer_pending);
   chan->pending_obscure_callback=1;
   return obscure_scheduled;
}
static int64_t obscure_time_compute(channel_t *chan){
    uint64_t long_now=monotime_coarse_absolute_msec();
    if(!chan->next_obscure_time_ms){
          int64_t obscure_timeout=obscure_get_timeout();
          if(!obscure_timeout)
    }
}
//send a cell on channel for obscure;
static void obscure_send_cell_for_callback(channel_t *chan){
  cell_t cell;
  if(!chan||chan->state!=CHANNEL_STATE_OPEN)return;
  memset(&cell,0,sizeof(cell));
  cell.command=CELL_OBSCURE;
  //the CELL_OBSCURE should be added into the cell commands;
  chan->write_cell(chan,&cell);
}