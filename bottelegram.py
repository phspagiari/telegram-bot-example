#!/usr/bin/env python
# -*- coding: utf-8 -*-

from telegram import (ReplyKeyboardMarkup, ReplyKeyboardRemove)
from telegram.ext import (Updater, CommandHandler, MessageHandler, Filters, RegexHandler,
                          ConversationHandler)
import requests

import json
import os
import binascii
import logging

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
level=logging.INFO)
logger = logging.getLogger(__name__)

TOKEN = os.getenv('TELEGRAM_TOKEN', '')
PROFILE, LOCATION = range(2)

JAIMINHO_URL = ""
JAIMINHO_QUERY_FILTER = "%s/profile-filters?latitude={}&longitude={}&profile={}" % JAIMINHO_URL
JAIMINHO_ALERT_POST = "%s/alert/" % JAIMINHO_URL
JAIMINHO_VINCULATION = "%s/user/me/notification/telegram" % JAIMINHO_URL
JAIMINHO_DETECT_USER = "%s/user/from-notification" % JAIMINHO_URL

global USER_INFO
USER_INFO = {}


PROFILE_MAPPER = {
    'Casado com filhos': 'marriedWithChildren',
    'Morar sozinho': 'singleLivingAlone',
    'Casado sem filhos': 'marriedWithoutChildren',
    'Morar com parceira(o)': 'livingWithPartner',
    'Morar com amigos': 'livingWithFriends',
    'Morar com família': 'livingWithFamily',
}


def start(bot, update):
    user = update.message.from_user
    global USER_INFO
    if user.id not in USER_INFO:
        USER_INFO[user.id] = {'profile': '', 'lat': '', 'lon': '', 'cuid': ''}

    reply_keyboard = [
        [
            'Casado com filhos',
            'Morar sozinho'
        ],
        [
            'Casado sem filhos',
            'Morar com parceira(o)',
        ],
        [
            'Morar com amigos',
            'Morar com família',
        ]
    ]

    update.message.reply_text(
        "Olá {}, eu sou o Robô do VR. Estou aqui para te ajudar a encontrar o imóvel dos seus sonhos! "
        "A qualquer momento você pode parar essa conversa digitando /cancelar.\n\n"
        "Vamos começar? "
        "Qual perfil se encaixa mais com você?".format(user.first_name),
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, resize_keyboard=True, one_time_keyboard=True))

    return PROFILE


def profile(bot, update):
    global USER_INFO
    user = update.message.from_user
    logger.info("[%s] Profile: %s" % (user.id, update.message.text))
    USER_INFO[user.id]['profile'] = update.message.text
    USER_INFO[user.id]['cuid'] = binascii.hexlify(os.urandom(16)).decode('utf-8')

    update.message.reply_text(
        'Ótimo! Agora me envie a localização no mapa de onde você deseja encontrar esse imovel!\n'
        )
    update.message.reply_text(
        'Para isso basta clicar no clips de papel, como se você fosse me enviar uma foto mas ao invés disso clique em Localização.\n'
        'Lembre-se que você não precisa enviar a localização de onde você está, você pode navegar pelo mapa e me mandar qualquer lugar do Brasil!\n\n'
        )
    logger.info("[%s] Waiting for location" % user.id)
    return LOCATION


def location(bot, update):
    global USER_INFO
    user = update.message.from_user
    user_location = update.message.location
    USER_INFO[user.id]['lat'] = user_location.latitude
    USER_INFO[user.id]['lon'] = user_location.longitude

    logger.info("[%s] Location: %f / %f"
                % (user.id, user_location.latitude, user_location.longitude))
    update.message.reply_text('Conheço muito bem esse lugar! Vou fazer alguns calculos rapidinho aqui.'
                            '')

    resp_filter = requests.get(
        JAIMINHO_QUERY_FILTER.format(
            USER_INFO[user.id]['lat'],
            USER_INFO[user.id]['lon'],
            PROFILE_MAPPER[USER_INFO[user.id]['profile']]
        ),
        headers={'content-type': 'application/json'}
    )
    logger.debug(resp_filter.content)
    if resp_filter.status_code != 200:
        logger.info("Something Went wrong")
        raise ValueError(resp.status_code)

    logger.info("[%s] Filters ready" % user.id)

    headers_alert = {'content-type': 'application/json', 'x-cuid': USER_INFO[user.id]['cuid']}
    filters_json = resp_filter.json()

    JAIMINHO_ALERT_PAYLOAD = {
        "user":{
            "cuid": USER_INFO[user.id]['cuid'],
            "notification_types":[]
        },
        "filters": json.dumps(filters_json['searchParams']),
        "name": "{} / {}".format(USER_INFO[user.id]['lat'], USER_INFO[user.id]['lon'])
    }
    resp_alert = requests.post(
        JAIMINHO_ALERT_POST,
        headers=headers_alert,
        data=json.dumps(JAIMINHO_ALERT_PAYLOAD)
    )

    logger.info(resp_alert.content)
    if resp_alert.status_code != 200:
        logger.info("Something Went wrong")
        raise ValueError(resp.status_code)

    logger.info("[%s] Alert created" % user.id)
    notification_data = {"data": user.id}
    r = requests.post(
        JAIMINHO_VINCULATION,
        headers={'content-type': 'application/json', 'x-cuid': USER_INFO[user.id]['cuid']},
        data=json.dumps(notification_data)
    )
    if r.status_code != 200:
        raise ValueError("Codigo Invalido %s" % r.status_code)


    logger.info("[%s] Finished the alert creation flux." % user.id)
    update.message.reply_text(
        "Tudo pronto %s, vou começar a procurar imóveis nesse lugar.\n"
        "Quando algo que for a sua cara aparecer eu vou te mandar!" % user.first_name
    )
    update.message.reply_text("Sempre que você quiser listar seus alertas basta me enviar /listar ok?")

    return ConversationHandler.END

def skip_location(bot, update):
    user = update.message.from_user
    logger.info("User %s did not send a location." % user.first_name)
    update.message.reply_text('Ok, infelizmente sem a localização não consigo continuar. '
                              'Espero conversar com você novamente e juntos encontrarmos a casa dos seus sonhos!'),

    return ConversationHandler.END

def cancel(bot, update):
    user = update.message.from_user
    logger.info("User %s canceled the conversation." % user.first_name)
    update.message.reply_text('Ok, como quiser! Espero conversar com você novamente e juntos encontrarmos a casa dos seus sonhos!', reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


def error(bot, update, error):
    logger.warn('Update "%s" caused error "%s"' % (update, error))


def list_alerts(bot, update):
    user = update.message.from_user

    cuid = _get_cuid(user.id)
    if not cuid:
        update.message.reply_text('Você ainda não tem nenhum alerta criado. Para criar, digite /start')
        return ConversationHandler.END

    resp_list = requests.get(
        JAIMINHO_ALERT_POST,
        headers={'content-type': 'application/json', 'x-cuid': cuid}
    )
    if resp_list.status_code != 200:
        raise ValueError("Wrong Status Code %s" % resp_list.status_code)

    alerts = resp_list.json()['results']
    if len(alerts) == 0:
        update.message.reply_text('Você ainda não tem nenhum alerta criado. Para criar, digite /start')
        return ConversationHandler.END

    update.message.reply_text("Você possui {} alertas configurados.\n".format(len(alerts)))
    # We can send the location of the alert: update.message.reply_location('-23.532423', '-46.718141')

    logger.info(alerts)

    message = [
        "Localização: {}\nImóveis não vistos {}\nhttp://<URL>/alertas/?user={}&show={}".format(
            result['name'], result['not_viewed'], cuid, result['id']) for result in alerts
    ]
    logger.info(message)
    update.message.reply_text('\n'.join(message))
    return ConversationHandler.END

def stop_bot(bot, update):
    return ConversationHandler.END

def remove_alert(bot, update):
    return ConversationHandler.END


def _get_cuid(user_id):
    resp = requests.get(
        "{}/?notificationData={}".format(JAIMINHO_DETECT_USER, user_id),
        headers={'content-type': 'application/json'}
    )

    if resp.status_code != 200:
        return None

    return resp.json()['cuid']

def main():
    logging.info("Initializing...")
    updater = Updater(TOKEN)
    dp = updater.dispatcher

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler('start', start),
            CommandHandler('listar', list_alerts),
            CommandHandler('parar', stop_bot),
            CommandHandler('remover', remove_alert)
        ],

        states={
            PROFILE: [RegexHandler('^(Casado\ com\ filhos|Morar\ sozinho|Casado\ sem\ filhos|Morar\ com\ parceira\(o\)|Morar\ com\ amigos|Morar\ com\ família)$', profile)],

            LOCATION: [MessageHandler(Filters.location, location),
                       CommandHandler('skip', skip_location)],
        },

        fallbacks=[
            CommandHandler('cancelar', cancel),
            ]
    )

    dp.add_handler(conv_handler)
    dp.add_error_handler(error)


    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
