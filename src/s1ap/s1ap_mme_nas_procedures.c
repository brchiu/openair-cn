/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "assertions.h"
#include "hashtable.h"
#include "log.h"
#include "msc.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "asn1_conversions.h"
#include "s1ap_common.h"
#include "s1ap_mme_encoder.h"
#include "s1ap_mme_itti_messaging.h"
#include "s1ap_mme.h"
#include "dynamic_memory_check.h"

/* Every time a new UE is associated, increment this variable.
   But care if it wraps to increment also the mme_ue_s1ap_id_has_wrapped
   variable. Limit: UINT32_MAX (in stdint.h).
*/
//static mme_ue_s1ap_id_t                 mme_ue_s1ap_id = 0;
//static bool                             mme_ue_s1ap_id_has_wrapped = false;

extern const char                      *s1ap_direction2String[];
extern hash_table_ts_t g_s1ap_mme_id2assoc_id_coll; // contains sctp association id, key is mme_ue_s1ap_id;


//------------------------------------------------------------------------------
int
s1ap_mme_handle_initial_ue_message (
  const sctp_assoc_id_t assoc_id,
  const sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{
  S1AP_InitialUEMessage_t                *container;
  S1AP_InitialUEMessage_IEs_t            *ie = NULL, *ie_e_tmsi, *ie_csg_id, *ie_gummei, *ie_cause;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *eNB_ref = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_S1AP);
  container = &pdu->choice.initiatingMessage.value.choice.InitialUEMessage;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);

  OAILOG_INFO (LOG_S1AP, "Received S1AP INITIAL_UE_MESSAGE eNB_UE_S1AP_ID " ENB_UE_S1AP_ID_FMT "\n", (enb_ue_s1ap_id_t)ie->value.choice.ENB_UE_S1AP_ID);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME, MSC_S1AP_ENB, NULL, 0, "0 initialUEMessage/%s assoc_id %u stream %u " ENB_UE_S1AP_ID_FMT " ",
          s1ap_direction2String[pdu->present - 1], assoc_id, stream, (enb_ue_s1ap_id_t)ie->value.choice.ENB_UE_S1AP_ID);

  if ((eNB_ref = s1ap_is_enb_assoc_id_in_list (assoc_id)) == NULL) {
    OAILOG_ERROR (LOG_S1AP, "Unknown eNB on assoc_id %d\n", assoc_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // eNB UE S1AP ID is limited to 24 bits
  enb_ue_s1ap_id = (enb_ue_s1ap_id_t) (ie->value.choice.ENB_UE_S1AP_ID & 0x00ffffff);
  OAILOG_INFO (LOG_S1AP, "New Initial UE message received with eNB UE S1AP ID: " ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
  ue_ref = s1ap_is_ue_enb_id_in_list (eNB_ref, enb_ue_s1ap_id);

  if (ue_ref == NULL) {
    tai_t                                   tai = {.plmn = {0}, .tac = INVALID_TAC_0000};
    gummei_t                                gummei = {.plmn = {0}, .mme_code = 0, .mme_gid = 0}; // initialized after
    as_stmsi_t                              s_tmsi = {.mme_code = 0, .m_tmsi = INVALID_M_TMSI};
    ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};
    csg_id_t                                csg_id = 0;

    /*
     * This UE eNB Id has currently no known s1 association.
     * * * * Create new UE context by associating new mme_ue_s1ap_id.
     * * * * Update eNB UE list.
     * * * * Forward message to NAS.
     */
    if ((ue_ref = s1ap_new_ue (assoc_id, enb_ue_s1ap_id)) == NULL) {
      // If we failed to allocate a new UE return -1
      OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Failed to allocate S1AP UE Context, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    ue_ref->s1_ue_state = S1AP_UE_WAITING_CSR;

    ue_ref->enb_ue_s1ap_id = enb_ue_s1ap_id;
    // Will be allocated by NAS
    ue_ref->mme_ue_s1ap_id = INVALID_MME_UE_S1AP_ID;
    
    ue_ref->s1ap_ue_context_rel_timer.id  = S1AP_TIMER_INACTIVE_ID;
    ue_ref->s1ap_ue_context_rel_timer.sec = S1AP_UE_CONTEXT_REL_COMP_TIMER;

    // On which stream we received the message
    ue_ref->sctp_stream_recv = stream;
    ue_ref->sctp_stream_send = ue_ref->enb->next_sctp_stream;

    /*
     * Increment the sctp stream for the eNB association.
     * If the next sctp stream is >= instream negociated between eNB and MME, wrap to first stream.
     * TODO: search for the first available stream instead.
     */

    /* 
     * TODO task#15456359.
     * Below logic seems to be incorrect , revisit it.
     */
    ue_ref->enb->next_sctp_stream += 1;
    if (ue_ref->enb->next_sctp_stream >= ue_ref->enb->instreams) {
      ue_ref->enb->next_sctp_stream = 1;
    }
    s1ap_dump_enb (ue_ref->enb);
    // TAI mandatory IE
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                               S1AP_ProtocolIE_ID_id_TAI, true);
    OCTET_STRING_TO_TAC (&ie->value.choice.TAI.tAC, tai.tac);
    DevAssert (ie->value.choice.TAI.pLMNidentity.size == 3);
    TBCD_TO_PLMN_T(&ie->value.choice.TAI.pLMNidentity, &tai.plmn);

    // CGI mandatory IE
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                               S1AP_ProtocolIE_ID_id_EUTRAN_CGI, true);
    DevAssert (ie->value.choice.EUTRAN_CGI.pLMNidentity.size == 3);
    TBCD_TO_PLMN_T(&ie->value.choice.EUTRAN_CGI.pLMNidentity, &ecgi.plmn);
    BIT_STRING_TO_CELL_IDENTITY (&ie->value.choice.EUTRAN_CGI.cell_ID, ecgi.cell_identity);

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_e_tmsi, container,
                               S1AP_ProtocolIE_ID_id_S_TMSI, false);
    if (ie_e_tmsi) {
      OCTET_STRING_TO_MME_CODE(&ie_e_tmsi->value.choice.S_TMSI.mMEC, s_tmsi.mme_code);
      OCTET_STRING_TO_M_TMSI(&ie_e_tmsi->value.choice.S_TMSI.m_TMSI, s_tmsi.m_tmsi);
    }

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_csg_id, container,
                               S1AP_ProtocolIE_ID_id_CSG_Id, false);
    if (ie_csg_id) {
      csg_id = BIT_STRING_to_uint32(&ie_csg_id->value.choice.CSG_Id);
    }

    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_gummei, container,
                               S1AP_ProtocolIE_ID_id_GUMMEI_ID, false);
    memset(&gummei, 0, sizeof(gummei));
    if (ie_gummei) {
      //TODO OCTET_STRING_TO_PLMN(&initialUEMessage_p->gummei_id.pLMN_Identity, gummei.plmn);
      OCTET_STRING_TO_MME_GID(&ie_gummei->value.choice.GUMMEI.mME_Group_ID, gummei.mme_gid);
      OCTET_STRING_TO_MME_CODE(&ie_gummei->value.choice.GUMMEI.mME_Code, gummei.mme_code);
    }
    /*
     * We received the first NAS transport message: initial UE message.
     * * * * Send a NAS ESTAeNBBLISH IND to NAS layer
     */
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie, container,
                               S1AP_ProtocolIE_ID_id_NAS_PDU, true);
    S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_InitialUEMessage_IEs_t, ie_cause, container,
                               S1AP_ProtocolIE_ID_id_RRC_Establishment_Cause, true);
#if ORIGINAL_CODE
    s1ap_mme_itti_nas_establish_ind (ue_ref->mme_ue_s1ap_id, ie->value.choice.NAS_PDU.buf, ie->value.choice.NAS_PDU.size,
        ie_cause->value.choice.RRC_Establishment_Cause, tai_tac);
#else
#if ITTI_LITE
    itf_mme_app_ll_initial_ue_message(assoc_id,
        ue_ref->enb_ue_s1ap_id,
        ue_ref->mme_ue_s1ap_id,
        ie->value.choice.NAS_PDU.buf,
        ie->value.choice.NAS_PDU.size,
        ie_cause->value.choice.RRC_Establishment_Cause,
        &tai, &cgi, &s_tmsi, &gummei);
#else
    s1ap_mme_itti_mme_app_initial_ue_message (assoc_id,
        ue_ref->enb->enb_id,
        ue_ref->enb_ue_s1ap_id,
        ue_ref->mme_ue_s1ap_id,
        ie->value.choice.NAS_PDU.buf,
        ie->value.choice.NAS_PDU.size,
        &tai,
        &ecgi,
        ie_cause->value.choice.RRC_Establishment_Cause,
        ie_e_tmsi ? &s_tmsi:NULL,
        ie_csg_id ? &csg_id:NULL,
        ie_gummei ? &gummei:NULL,
        NULL, // CELL ACCESS MODE
        NULL, // GW Transport Layer Address
        NULL  //Relay Node Indicator
        );
#endif
#endif
  } else {
    OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Duplicate ENB_UE_S1AP_ID. Ignoring the message, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
  }

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_handle_uplink_nas_transport (
  const sctp_assoc_id_t assoc_id,
  __attribute__((unused)) const sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{
  S1AP_UplinkNASTransport_t              *container;
  S1AP_UplinkNASTransport_IEs_t          *ie = NULL, *ie_nas_pdu = NULL;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *enb_ref = NULL;
  tai_t                                   tai = {.plmn = {0}, .tac = INVALID_TAC_0000};
  ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};
  mme_ue_s1ap_id_t                        mme_ue_s1ap_id = 0;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_S1AP);
  container = &pdu->choice.initiatingMessage.value.choice.UplinkNASTransport;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);
  enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID, true);
  mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;

  if (INVALID_MME_UE_S1AP_ID == ie->value.choice.MME_UE_S1AP_ID) {
    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID unknown\n");

    enb_ref = s1ap_is_enb_assoc_id_in_list (assoc_id);

    if (!(ue_ref = s1ap_is_ue_enb_id_in_list ( enb_ref, (enb_ue_s1ap_id_t)ie->value.choice.MME_UE_S1AP_ID))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this enb_ue_s1ap_id: " ENB_UE_S1AP_ID_FMT "\n",
          (enb_ue_s1ap_id_t)ie->value.choice.MME_UE_S1AP_ID);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  } else {
    OAILOG_INFO (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT "\n",
        (mme_ue_s1ap_id_t)ie->value.choice.MME_UE_S1AP_ID);

    if (!(ue_ref = s1ap_is_ue_mme_id_in_list (ie->value.choice.MME_UE_S1AP_ID))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this mme_ue_s1ap_id: " MME_UE_S1AP_ID_FMT "\n",
          (mme_ue_s1ap_id_t)ie->value.choice.MME_UE_S1AP_ID);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  }

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie_nas_pdu, container,
                             S1AP_ProtocolIE_ID_id_NAS_PDU, true);

  if (S1AP_UE_CONNECTED != ue_ref->s1_ue_state) {
    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT while UE in state != S1AP_UE_CONNECTED\n");
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
                        s1ap_direction2String[pdu->present - 1],
                        (mme_ue_s1ap_id_t)mme_ue_s1ap_id,
                        (enb_ue_s1ap_id_t)enb_ue_s1ap_id,
                        ie_nas_pdu->value.choice.NAS_PDU.size);

    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  // TAI mandatory IE
  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_TAI, true);
  OCTET_STRING_TO_TAC (&ie->value.choice.TAI.tAC, tai.tac);
  DevAssert (ie->value.choice.TAI.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&ie->value.choice.TAI.pLMNidentity, &tai.plmn);

  // CGI mandatory IE
  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_UplinkNASTransport_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_EUTRAN_CGI, true);
  DevAssert (ie->value.choice.EUTRAN_CGI.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&ie->value.choice.EUTRAN_CGI.pLMNidentity, &ecgi.plmn);
  BIT_STRING_TO_CELL_IDENTITY (&ie->value.choice.EUTRAN_CGI.cell_ID, ecgi.cell_identity);

  // TODO optional GW Transport Layer Address


  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
                      s1ap_direction2String[pdu->present - 1],
                      (mme_ue_s1ap_id_t)mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)enb_ue_s1ap_id,
                      ie_nas_pdu->value.choice.NAS_PDU.size);

  bstring b = blk2bstr(ie_nas_pdu->value.choice.NAS_PDU.buf, ie_nas_pdu->value.choice.NAS_PDU.size);
  s1ap_mme_itti_nas_uplink_ind (mme_ue_s1ap_id,
                                &b,
                                &tai,
                                &ecgi);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_handle_nas_non_delivery (
    __attribute__((unused)) sctp_assoc_id_t assoc_id,
  sctp_stream_id_t stream,
  S1AP_S1AP_PDU_t *pdu)
{
  S1AP_NASNonDeliveryIndication_t        *container;
  S1AP_NASNonDeliveryIndication_IEs_t    *ie = NULL, *ie_nas_pdu;
  ue_description_t                       *ue_ref = NULL;
  mme_ue_s1ap_id_t                        mme_ue_s1ap_id = 0;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_S1AP);

  container = &pdu->choice.initiatingMessage.value.choice.NASNonDeliveryIndication;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID, true);
  mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID, true);
  enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie_nas_pdu, container,
                             S1AP_ProtocolIE_ID_id_NAS_PDU, true);

  S1AP_FIND_PROTOCOLIE_BY_ID(S1AP_NASNonDeliveryIndication_IEs_t, ie, container,
                             S1AP_ProtocolIE_ID_id_Cause, true);

  /*
   * UE associated signalling on stream == 0 is not valid.
   */
  if (stream == 0) {
    OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message on invalid sctp stream 0\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT "\n",
      (mme_ue_s1ap_id_t)mme_ue_s1ap_id, (enb_ue_s1ap_id_t)enb_ue_s1ap_id);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 NASNonDeliveryIndication/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " cause %u nas len %u",
                      s1ap_direction2String[pdu->present - 1],
                      (mme_ue_s1ap_id_t)mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)enb_ue_s1ap_id,
                      ie->value.choice.Cause,
                      ie_nas_pdu->value.choice.NAS_PDU.size);

  if ((ue_ref = s1ap_is_ue_mme_id_in_list (mme_ue_s1ap_id))
      == NULL) {
    OAILOG_DEBUG (LOG_S1AP, "No UE is attached to this mme UE s1ap id: " MME_UE_S1AP_ID_FMT "\n", (mme_ue_s1ap_id_t)mme_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  if (ue_ref->s1_ue_state != S1AP_UE_CONNECTED) {
    OAILOG_DEBUG (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION while UE in state != S1AP_UE_CONNECTED\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  //TODO: forward NAS PDU to NAS
  s1ap_mme_itti_nas_non_delivery_ind (mme_ue_s1ap_id,
                                      ie_nas_pdu->value.choice.NAS_PDU.buf,
                                      ie_nas_pdu->value.choice.NAS_PDU.size,
                                      &ie->value.choice.Cause);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_generate_downlink_nas_transport (
  const enb_ue_s1ap_id_t enb_ue_s1ap_id,
  const mme_ue_s1ap_id_t ue_id,
  STOLEN_REF bstring *payload)
{
  ue_description_t                       *ue_ref = NULL;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  void                                   *id = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);

  // Try to retrieve SCTP assoication id using mme_ue_s1ap_id
  if (HASH_TABLE_OK ==  hashtable_ts_get (&g_s1ap_mme_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id)) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    enb_description_t  *enb_ref = s1ap_is_enb_assoc_id_in_list (sctp_assoc_id);
    if (enb_ref) {
      ue_ref = s1ap_is_ue_enb_id_in_list (enb_ref,enb_ue_s1ap_id);
    } else {
      OAILOG_ERROR (LOG_S1AP, "No eNB for SCTP association id %d \n", sctp_assoc_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  }
  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = s1ap_is_ue_mme_id_in_list (ue_id);
  }
  // finally!
  if (!ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the MME shall allocate a unique MME UE S1AP ID to be used for the UE.
     */
    OAILOG_WARNING (LOG_S1AP, "Unknown UE MME ID " MME_UE_S1AP_ID_FMT ", This case is not handled right now\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  } else {
    /*
     * We have fount the UE in the list.
     * * * * Create new IE list message and encode it.
     */
    S1AP_S1AP_PDU_t                        pdu = {0};
    S1AP_DownlinkNASTransport_t            *out;
    S1AP_DownlinkNASTransport_IEs_t        *ie = NULL;

    memset(&pdu, 0, sizeof(pdu));
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_downlinkNASTransport;
    pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
    pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_DownlinkNASTransport;
    out = &pdu.choice.initiatingMessage.value.choice.DownlinkNASTransport;

    ue_ref->s1_ue_state = S1AP_UE_CONNECTED;

    /*
     * Setting UE informations with the ones fount in ue_ref
     */

    /* mandatory */
    ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    /* mandatory */
    ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
    /* mandatory */
    ie = (S1AP_DownlinkNASTransport_IEs_t *)calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_NAS_PDU;
    /*eNB
     * Fill in the NAS pdu
     */
    OCTET_STRING_fromBuf (&ie->value.choice.NAS_PDU, (char *)bdata(*payload), blength(*payload));
    bdestroy(*payload);
    *payload = NULL;
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

    if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
      // TODO: handle something
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    OAILOG_NOTICE (LOG_S1AP, "Send S1AP DOWNLINK_NAS_TRANSPORT message ue_id = " MME_UE_S1AP_ID_FMT " MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
                ue_id, (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id);
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 downlinkNASTransport/initiatingMessage ue_id " MME_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id" ENB_UE_S1AP_ID_FMT " nas length %u",
                        ue_id, (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id, length);
    bstring b = blk2bstr(buffer_p, length);
    s1ap_mme_itti_send_sctp_request (&b , ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  }

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
void
s1ap_handle_conn_est_cnf (
  const itti_mme_app_connection_establishment_cnf_t * const conn_est_cnf_pP)
{
  /*
   * We received create session response from S-GW on S11 interface abstraction.
   * At least one bearer has been established. We can now send s1ap initial context setup request
   * message to eNB.
   */
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  S1AP_S1AP_PDU_t                         pdu = {0};
  S1AP_InitialContextSetupRequest_t      *out;
  S1AP_InitialContextSetupRequestIEs_t   *ie = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (conn_est_cnf_pP != NULL);
  
  ue_ref = s1ap_is_ue_mme_id_in_list (conn_est_cnf_pP->nas_conn_est_cnf.ue_id);
  if (!ue_ref) {
    OAILOG_ERROR (LOG_S1AP, "This mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") is not attached to any UE context\n", conn_est_cnf_pP->nas_conn_est_cnf.ue_id);
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /*
   * Start the outcome response timer.
   * * * * When time is reached, MME consider that procedure outcome has failed.
   */
  //     timer_setup(mme_config.s1ap_config.outcome_drop_timer_sec, 0, TASK_S1AP, INSTANCE_DEFAULT,
  //                 TIMER_ONE_SHOT,
  //                 NULL,
  //                 &ue_ref->outcome_response_timer_id);
  /*
   * Insert the timer in the MAP of mme_ue_s1ap_id <-> timer_id
   */
  //     s1ap_timer_insert(ue_ref->mme_ue_s1ap_id, ue_ref->outcome_response_timer_id);

  memset(&pdu, 0, sizeof(pdu));
  pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
  pdu.choice.initiatingMessage.procedureCode = S1AP_ProcedureCode_id_InitialContextSetup;
  pdu.choice.initiatingMessage.criticality = S1AP_Criticality_ignore;
  pdu.choice.initiatingMessage.value.present = S1AP_InitiatingMessage__value_PR_InitialContextSetupRequest;
  out = &pdu.choice.initiatingMessage.value.choice.InitialContextSetupRequest;

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_MME_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->mme_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_ENB_UE_S1AP_ID;
  ie->value.choice.ENB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /*
   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
   */

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_uEaggregateMaximumBitrate;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UEAggregateMaximumBitrate;
  asn_uint642INTEGER (&ie->value.choice.UEAggregateMaximumBitrate.uEaggregateMaximumBitRateDL, conn_est_cnf_pP->ambr.br_dl);
  asn_uint642INTEGER (&ie->value.choice.UEAggregateMaximumBitrate.uEaggregateMaximumBitRateUL, conn_est_cnf_pP->ambr.br_ul);
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_E_RABToBeSetupListCtxtSUReq;
  {
    S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t  *e_rab_tobesetup_item = (S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t *)calloc(1, sizeof(S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t));
    S1AP_E_RABToBeSetupItemCtxtSUReq_t *e_RABToBeSetup;

    e_rab_tobesetup_item->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq;
    e_rab_tobesetup_item->criticality = S1AP_Criticality_reject;
    e_rab_tobesetup_item->value.present = S1AP_E_RABToBeSetupItemCtxtSUReqIEs__value_PR_E_RABToBeSetupItemCtxtSUReq;
    e_RABToBeSetup = &e_rab_tobesetup_item->value.choice.E_RABToBeSetupItemCtxtSUReq;

    e_RABToBeSetup->e_RAB_ID = conn_est_cnf_pP->eps_bearer_id;     //5;
    e_RABToBeSetup->e_RABlevelQoSParameters.qCI = conn_est_cnf_pP->bearer_qos_qci;

    if (conn_est_cnf_pP->nas_conn_est_cnf.nas_msg != NULL) {
      // NAS PDU is optional in rab_setup
      e_RABToBeSetup->nAS_PDU = (S1AP_NAS_PDU_t *)calloc(1, sizeof(S1AP_NAS_PDU_t));
      e_RABToBeSetup->nAS_PDU->size = conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->slen;
      e_RABToBeSetup->nAS_PDU->buf  = conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->data;
    }
#if ORIGINAL_S1AP_CODE
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = S1AP_PriorityLevel_lowest;
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = S1AP_Pre_emptionCapability_shall_not_trigger_pre_emption;
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = S1AP_Pre_emptionVulnerability_not_pre_emptable;
#else
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = conn_est_cnf_pP->bearer_qos_prio_level;
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = conn_est_cnf_pP->bearer_qos_pre_emp_capability;
    e_RABToBeSetup->e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = conn_est_cnf_pP->bearer_qos_pre_emp_vulnerability;
#endif
    /*
     * Set the GTP-TEID. This is the S1-U S-GW TEID
     */
    INT32_TO_OCTET_STRING (conn_est_cnf_pP->bearer_s1u_sgw_fteid.teid, &e_RABToBeSetup->gTP_TEID);

    /*
     * S-GW IP address(es) for user-plane
     */
    if (conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv4) {
      e_RABToBeSetup->transportLayerAddress.buf = calloc (4, sizeof (uint8_t));
      /*
       * Only IPv4 supported
       */
      memcpy (e_RABToBeSetup->transportLayerAddress.buf, &conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv4_address, 4);
      offset += 4;
      e_RABToBeSetup->transportLayerAddress.size = 4;
      e_RABToBeSetup->transportLayerAddress.bits_unused = 0;
    }

    if (conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6) {
      if (offset == 0) {
        /*
         * Both IPv4 and IPv6 provided
         */
        /*
         * TODO: check memory allocation
         */
        e_RABToBeSetup->transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
      } else {
        /*
         * Only IPv6 supported
         */
        /*
         * TODO: check memory allocation
         */
        e_RABToBeSetup->transportLayerAddress.buf = realloc (e_RABToBeSetup->transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
      }

      memcpy (&e_RABToBeSetup->transportLayerAddress.buf[offset], conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6_address, 16);
      e_RABToBeSetup->transportLayerAddress.size = 16 + offset;
      e_RABToBeSetup->transportLayerAddress.bits_unused = 0;
    }

    ASN_SEQUENCE_ADD(&ie->value.choice.E_RABToBeSetupListCtxtSUReq.list, e_rab_tobesetup_item);
  }
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_UESecurityCapabilities;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities;
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf = (uint8_t *) & conn_est_cnf_pP->security_capabilities_encryption_algorithms;

  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf = (uint8_t *) calloc(1, 2);
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf[0] = ((uint8_t *) & conn_est_cnf_pP->security_capabilities_encryption_algorithms)[0];
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.buf[1] = ((uint8_t *) & conn_est_cnf_pP->security_capabilities_encryption_algorithms)[1];
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.size = 2;
  ie->value.choice.UESecurityCapabilities.encryptionAlgorithms.bits_unused = 0;
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf = (uint8_t *) calloc(1, 2);
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf[0] = ((uint8_t *) & conn_est_cnf_pP->security_capabilities_integrity_algorithms)[0];
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.buf[1] = ((uint8_t *) & conn_est_cnf_pP->security_capabilities_integrity_algorithms)[1]; 
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.size = 2;
  ie->value.choice.UESecurityCapabilities.integrityProtectionAlgorithms.bits_unused = 0;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_integrity_algorithms);

  /* mandatory */
  ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
  ie->id = S1AP_ProtocolIE_ID_id_SecurityKey;
  ie->criticality = S1AP_Criticality_reject;
  ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_SecurityKey;
  if (conn_est_cnf_pP->kenb) {
    ie->value.choice.SecurityKey.buf = calloc (32, sizeof(uint8_t));
    memcpy (ie->value.choice.SecurityKey.buf, conn_est_cnf_pP->kenb, 32);
    ie->value.choice.SecurityKey.size = 32;
  } else {
    OAILOG_DEBUG (LOG_S1AP, "No kenb\n");
    ie->value.choice.SecurityKey.buf = NULL;
    ie->value.choice.SecurityKey.size = 0;
  }
  ie->value.choice.SecurityKey.bits_unused = 0;
  ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);

  /* optional */
  /*
   * Only add capability information if it's not empty.
   */
  if (conn_est_cnf_pP->ue_radio_cap_length) {
    OAILOG_DEBUG (LOG_S1AP, "UE radio capability found, adding to message\n");

    ie = (S1AP_InitialContextSetupRequestIEs_t *)calloc(1, sizeof(S1AP_InitialContextSetupRequestIEs_t));
    ie->id = S1AP_ProtocolIE_ID_id_UERadioCapability;
    ie->criticality = S1AP_Criticality_ignore;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UERadioCapability;
    OCTET_STRING_fromBuf(&ie->value.choice.UERadioCapability,
                        (const char*) conn_est_cnf_pP->ue_radio_capabilities,
                         conn_est_cnf_pP->ue_radio_cap_length);
    ASN_SEQUENCE_ADD(&out->protocolIEs.list, ie);
  }

  if (s1ap_mme_encode_pdu (&pdu, &buffer_p, &length) < 0) {
    // TODO: handle something
    DevMessage ("Failed to encode initial context setup request message\n");
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_INITIAL_CONTEXT_SETUP_REQUEST message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 InitialContextSetup/initiatingMessage mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas length %u",
                      (mme_ue_s1ap_id_t)ue_ref->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)ue_ref->enb_ue_s1ap_id,
                      conn_est_cnf_pP->nas_conn_est_cnf.nas_msg ? conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->slen : 0);
  bstring b = blk2bstr(buffer_p, length);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}
//------------------------------------------------------------------------------
void
s1ap_handle_mme_ue_id_notification (
  const itti_mme_app_s1ap_mme_ue_id_notification_t * const notification_p)
{

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (notification_p != NULL);
  s1ap_notified_new_ue_mme_s1ap_id_association (
                          notification_p->sctp_assoc_id, notification_p->enb_ue_s1ap_id, notification_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}
