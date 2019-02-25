-- Copyright (c) 2019
-- Mainflux
--
-- SPDX-License-Identifier: Apache-2.0


module Main exposing (Model, Msg(..), init, main, subscriptions, update, view)

import Bootstrap.Button as Button
import Bootstrap.ButtonGroup as ButtonGroup
import Bootstrap.CDN as CDN
import Bootstrap.Form as Form
import Bootstrap.Form.Checkbox as Checkbox
import Bootstrap.Form.Fieldset as Fieldset
import Bootstrap.Form.Input as Input
import Bootstrap.Form.Radio as Radio
import Bootstrap.Form.Select as Select
import Bootstrap.Form.Textarea as Textarea
import Bootstrap.Grid as Grid
import Bootstrap.Grid.Col as Col
import Bootstrap.Grid.Row as Row
import Bootstrap.Utilities.Spacing as Spacing
import Browser
import Browser.Navigation as Nav
import Channel
import Connection
import Dashboard
import Debug exposing (log)
import Error
import Html exposing (..)
import Html.Attributes exposing (..)
import Http
import Json.Decode exposing (Decoder, field, string)
import Json.Encode as Encode
import Message
import Thing
import Url
import Url.Parser as UrlParser exposing ((</>))
import User
import Version



-- MAIN


main : Program () Model Msg
main =
    Browser.application
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = LinkClicked
        }



-- MODEL


type alias Model =
    { key : Nav.Key
    , user : User.Model
    , version : Version.Model
    , dashboard : Dashboard.Model
    , channel : Channel.Model
    , thing : Thing.Model
    , connection : Connection.Model
    , message : Message.Model
    , view : String
    }


init : () -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init _ url key =
    ( Model key
        User.initial
        Version.initial
        Dashboard.initial
        Channel.initial
        Thing.initial
        Connection.initial
        Message.initial
        (parse url)
    , Cmd.none
    )



-- URL PARSER


type alias Route =
    ( String, Maybe String )


parse : Url.Url -> String
parse url =
    UrlParser.parse
        (UrlParser.map Tuple.pair (UrlParser.string </> UrlParser.fragment identity))
        url
        |> (\route ->
                case route of
                    Just r ->
                        Tuple.first r

                    Nothing ->
                        ""
           )


type Msg
    = LinkClicked Browser.UrlRequest
    | UrlChanged Url.Url
    | UserMsg User.Msg
    | VersionMsg Version.Msg
    | DashboardMsg Dashboard.Msg
    | ChannelMsg Channel.Msg
    | ThingMsg Thing.Msg
    | ConnectionMsg Connection.Msg
    | MessageMsg Message.Msg
    | Dashboard
    | Login Msg
    | Channels
    | Things
    | Connection
    | Messages


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        LinkClicked urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.pushUrl model.key (Url.toString url) )

                Browser.External href ->
                    ( model, Cmd.none )

        UrlChanged url ->
            ( { model | view = parse url }
            , Cmd.none
            )

        UserMsg subMsg ->
            let
                ( updatedUser, userCmd ) =
                    User.update subMsg model.user
            in
            case subMsg of
                User.GotToken _ ->
                    if String.length updatedUser.token > 0 then
                        logIn model updatedUser Version.GetVersion Thing.RetrieveThings Channel.RetrieveChannels

                    else
                        ( model, Cmd.none )

                _ ->
                    ( { model | user = updatedUser }, Cmd.map UserMsg userCmd )

        DashboardMsg subMsg ->
            let
                ( updatedDashboard, dashboardCmd ) =
                    Dashboard.update subMsg model.dashboard
            in
            ( { model | dashboard = updatedDashboard }, Cmd.map DashboardMsg dashboardCmd )

        ChannelMsg subMsg ->
            let
                ( updatedChannel, channelCmd ) =
                    Channel.update subMsg model.channel model.user.token
            in
            ( { model | channel = updatedChannel }, Cmd.map ChannelMsg channelCmd )

        ThingMsg subMsg ->
            let
                ( updatedThing, thingCmd ) =
                    Thing.update subMsg model.thing model.user.token
            in
            ( { model | thing = updatedThing }, Cmd.map ThingMsg thingCmd )

        ConnectionMsg subMsg ->
            let
                ( updatedConnection, connectionCmd ) =
                    Connection.update subMsg model.connection model.user.token
            in
            ( { model | connection = updatedConnection }, Cmd.map ConnectionMsg connectionCmd )

        MessageMsg subMsg ->
            let
                ( updatedMessage, messageCmd ) =
                    Message.update subMsg model.message model.user.token
            in
            ( { model | message = updatedMessage }, Cmd.map MessageMsg messageCmd )

        VersionMsg subMsg ->
            let
                ( updatedVersion, versionCmd ) =
                    Version.update subMsg model.version
            in
            ( { model | version = updatedVersion }, Cmd.map VersionMsg versionCmd )

        Dashboard ->
            ( { model | view = "dashboard" }, Cmd.none )

        Login subMsg ->
            case subMsg of
                VersionMsg vMsg ->
                    let
                        ( updatedVersion, versionCmd ) =
                            Version.update vMsg model.version
                    in
                    ( { model | version = updatedVersion }, Cmd.map VersionMsg versionCmd )

                ThingMsg tMsg ->
                    let
                        ( updatedThing, thingCmd ) =
                            Thing.update tMsg model.thing model.user.token
                    in
                    ( { model | thing = updatedThing }, Cmd.map ThingMsg thingCmd )

                ChannelMsg cMsg ->
                    let
                        ( updatedChannel, channelCmd ) =
                            Channel.update cMsg model.channel model.user.token
                    in
                    ( { model | channel = updatedChannel }, Cmd.map ChannelMsg channelCmd )

                _ ->
                    ( { model | view = "dashboard" }, Cmd.none )

        Things ->
            ( { model | view = "things" }, Cmd.none )

        Channels ->
            ( { model | view = "channels" }, Cmd.none )

        Connection ->
            let
                ( _, thingsCmd ) =
                    Connection.update (Connection.ThingMsg Thing.RetrieveThings) Connection.initial model.user.token

                ( _, channelsCmd ) =
                    Connection.update (Connection.ChannelMsg Channel.RetrieveChannels) Connection.initial model.user.token
            in
            ( { model | view = "connection" }, Cmd.map ConnectionMsg (Cmd.batch [ thingsCmd, channelsCmd ]) )

        Messages ->
            let
                ( _, thingsCmd ) =
                    Message.update (Message.ThingMsg Thing.RetrieveThings) Message.initial model.user.token
            in
            ( { model | view = "messages" }, Cmd.map MessageMsg thingsCmd )


logIn : Model -> User.Model -> Version.Msg -> Thing.Msg -> Channel.Msg -> ( Model, Cmd Msg )
logIn model user versionMsg thingMsg channelMsg =
    let
        ( updatedVersion, versionCmd ) =
            Version.update versionMsg model.version

        ( updatedThing, thingCmd ) =
            Thing.update thingMsg model.thing user.token

        ( updatedChannel, channelCmd ) =
            Channel.update channelMsg model.channel user.token
    in
    ( { model | user = user }
    , Cmd.map Login
        (Cmd.batch
            [ Cmd.map VersionMsg versionCmd
            , Cmd.map ThingMsg thingCmd
            , Cmd.map ChannelMsg channelCmd
            ]
        )
    )



-- Menu subMsg ->
--     ( model, Cmd.none )
-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none



-- VIEW


mfStylesheet : Html msg
mfStylesheet =
    node "link"
        [ rel "stylesheet"
        , href "./css/mainflux.css"
        ]
        []


view : Model -> Browser.Document Msg
view model =
    { title = "Gateflux"
    , body =
        let
            loggedIn : Bool
            loggedIn =
                if String.length model.user.token > 0 then
                    True

                else
                    False

            buttonAttrs =
                Button.attrs [ style "text-align" "left" ]

            menu =
                if loggedIn then
                    [ ButtonGroup.linkButton [ Button.primary, Button.onClick Dashboard, buttonAttrs ] [ text "dashboard" ]
                    , ButtonGroup.linkButton [ Button.primary, Button.onClick Things, buttonAttrs ] [ text "things" ]
                    , ButtonGroup.linkButton [ Button.primary, Button.onClick Channels, buttonAttrs ] [ text "channels" ]
                    , ButtonGroup.linkButton [ Button.primary, Button.onClick Connection, buttonAttrs ] [ text "connection" ]
                    , ButtonGroup.linkButton [ Button.primary, Button.onClick Messages, buttonAttrs ] [ text "messages" ]
                    ]

                else
                    []

            header =
                if loggedIn then
                    Grid.row []
                        [ Grid.col [ Col.attrs [] ] [ text model.user.email ]
                        , Grid.col [ Col.attrs [ align "right" ] ] [ Button.button [ Button.roleLink, Button.attrs [ Spacing.ml1 ], Button.onClick User.LogOut ] [ text "logout" ] ]
                        ]

                else
                    Grid.row []
                        [ Grid.col [ Col.attrs [] ] [] ]

            content =
                if loggedIn then
                    case model.view of
                        "dashboard" ->
                            Html.map DashboardMsg (Dashboard.view model.dashboard model.version.response model.thing.things.total model.channel.channels.total)

                        "channels" ->
                            Html.map ChannelMsg (Channel.view model.channel)

                        "things" ->
                            Html.map ThingMsg (Thing.view model.thing)

                        "connection" ->
                            Html.map ConnectionMsg (Connection.view model.connection)

                        "messages" ->
                            Html.map MessageMsg (Message.view model.message)

                        _ ->
                            Html.map DashboardMsg (Dashboard.view model.dashboard model.version.response model.thing.things.total model.channel.channels.total)

                else
                    Html.map UserMsg (User.view model.user)
        in
        -- we use Bootstrap container defined at http://elm-bootstrap.info/grid
        [ Grid.containerFluid []
            [ CDN.stylesheet -- creates an inline style node with the Bootstrap CSS
            , mfStylesheet
            , Grid.row [ Row.attrs [ style "height" "100vh" ] ]
                [ Grid.col
                    [ Col.attrs
                        [ style "background-color" "#113f67"
                        , style "padding" "0"
                        , style "color" "white"
                        ]
                    ]
                    [ Grid.row []
                        [ Grid.col
                            [ Col.attrs [] ]
                            [ h3 [] [ text "Mainflux" ] ]
                        ]
                    , Grid.row []
                        [ Grid.col
                            [ Col.attrs [] ]
                            [ ButtonGroup.linkButtonGroup
                                [ ButtonGroup.vertical
                                , ButtonGroup.attrs [ style "width" "100%" ]
                                ]
                                menu
                            ]
                        ]
                    ]
                , Grid.col
                    [ Col.xs10
                    , Col.attrs []
                    ]
                    [ Html.map UserMsg header
                    , Grid.row []
                        [ Grid.col
                            [ Col.attrs [] ]
                            [ content ]
                        ]
                    ]
                ]
            ]
        ]
    }
