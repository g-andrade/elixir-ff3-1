# credo:disable-for-this-file Credo.Check.Design.AliasUsage
# credo:disable-for-this-file Credo.Check.Readability.ModuleNames
defmodule FF1_Test do
  use ExUnit.Case, async: true

  ## Official NIST FF1 sample vectors, from the "Examples with Intermediate
  ## Values" published for SP 800-38G:
  ## https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
  ##
  ## Cross-checked against capitalone/fpe's ff1_test.go. The radix-36 vectors use
  ## a lowercase plaintext/ciphertext in the source; here they are upcased because
  ## the Builtin base-36 codec is case-insensitive on input and canonicalizes its
  ## output to uppercase.

  test "NIST FF1 sample 1 (AES-128, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      "",
      "0123456789",
      "2433477484",
      10
    )
  end

  test "NIST FF1 sample 2 (AES-128, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      hex("39383736353433323130"),
      "0123456789",
      "6124200773",
      10
    )
  end

  test "NIST FF1 sample 3 (AES-128, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3C"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("a9tv40mll9kdu509eum"),
      36
    )
  end

  test "NIST FF1 sample 4 (AES-192, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      "",
      "0123456789",
      "2830668132",
      10
    )
  end

  test "NIST FF1 sample 5 (AES-192, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      hex("39383736353433323130"),
      "0123456789",
      "2496655549",
      10
    )
  end

  test "NIST FF1 sample 6 (AES-192, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("xbj3kv35jrawxv32ysr"),
      36
    )
  end

  test "NIST FF1 sample 7 (AES-256, radix 10, empty tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      "",
      "0123456789",
      "6657667009",
      10
    )
  end

  test "NIST FF1 sample 8 (AES-256, radix 10, 10-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      hex("39383736353433323130"),
      "0123456789",
      "1001623463",
      10
    )
  end

  test "NIST FF1 sample 9 (AES-256, radix 36, 11-byte tweak)" do
    check_test_vector(
      hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
      hex("3737373770717273373737"),
      String.upcase("0123456789abcdefghi"),
      String.upcase("xs8a0azh2avyalyzuwd"),
      36
    )
  end

  test "very large alphabet" do
    alphabet =
      String.replace(
        """
        0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
        opqrstuvwxyzÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäå
        æçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖė
        ĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉ
        ŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻ
        żŽžſΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρςστυφ
        χψωЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮ
        ЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠ
        ѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙ
        ҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋ
        ӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽ
        ӾӿԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖաբգդեզէըթժ
        իլխծկհձղճմյնշոչպջռսվտրցւփքօֆאבגדהוזחטיךכלםמןנסעףפץ
        צקרשתابةتثجحخدذرزسشصضطظعغػؼؽؾؿـفقكلمنهوىيაბგდევზთი
        კლმნოპჟრსტუფქღყშჩცძწჭხჯჰჱჲჳჴჵჶჷჸჹჺぁあぃいぅうぇえぉおかがきぎくぐ
        けげこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺほぼぽまみむめも
        ゃやゅゆょよらりるれろゎわゐゑをんゔゕゖァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾ
        タダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰ
        ヱヲンヴヵヶヷヸヹヺ一丁丂七丄丅丆万丈三上下丌不与丏丐丑丒专且丕世丗丘丙业丛东丝丞丟丠両丢丣两严並丧
        丨丩个丫丬中丮丯丰丱串丳临丵丶丷丸丹为主丼丽举丿乀乁乂乃乄久乆乇么义乊之乌乍乎乏乐乑乒乓乔乕乖乗乘乙
        乚乛乜九乞也习乡乢乣乤乥书乧乨乩乪乫乬乭乮乯买乱乲乳乴乵乶乷乸乹乺乻乼乽乾乿亀亁亂亃亄亅了亇予争亊事
        二亍于亏亐云互亓五井亖亗亘亙亚些亜亝亞亟亠亡亢亣交亥亦产亨亩亪享京亭亮亯亰亱亲亳亴亵亶亷亸亹人亻亼亽
        亾亿什仁仂仃仄仅仆仇仈仉今介仌仍从仏仐仑仒仓仔仕他仗付仙仚仛仜仝仞仟仠仡仢代令以仦仧仨仩仪仫们仭仮仯
        仰仱仲仳仴仵件价仸仹仺任仼份仾仿
        """,
        ["\n", "\r"],
        ""
      )

    assert alphabet |> String.codepoints() |> length() === 1166
    assert String.length(alphabet) === 1166

    check_test_vector(
      <<2, 53, 38, 51, 205, 8, 101, 47, 25, 85, 92, 90, 209, 164, 129, 255>>,
      "",
      "mmmmmh",
      "ド乄νѶպし",
      alphabet
    )

    check_test_vector(
      <<2, 53, 38, 51, 205, 8, 101, 47, 25, 85, 92, 90, 209, 164, 129, 255>>,
      "",
      "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmh",
      "乻É亶ӻЩ亅òՄfπՓҞ仠よωŭل为Ū亩ê仨ĎθタĉռѥÓӦ亳ӊҒقUģĳ乚亜Җբっ",
      alphabet
    )
  end

  ## Helpers

  defp check_test_vector(key, tweak, plaintext, ciphertext, radix_or_alphabet) do
    {:ok, fpe} = FPE.new(key, :ff1, radix_or_alphabet)
    assert FPE.encrypt!(fpe, tweak, plaintext) == ciphertext
    assert FPE.decrypt!(fpe, tweak, ciphertext) == plaintext
  end

  defp hex(string), do: Base.decode16!(string, case: :mixed)
end
