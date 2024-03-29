
namespace PE_CONVERTER{
    class Converter{
    public:
        Converter(Converter const&) = delete;
        void operator=(Converter const&) = delete;

        static Converter& getConverter();

    private:
        Converter(){}
    };
};

