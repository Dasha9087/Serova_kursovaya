import java.io.*;
import java.util.*;

enum UserRole {
    ROLE_ADMIN(1),
    ROLE_USER(2);

    private final int value;

    UserRole(int value) {
        this.value = value;
    }

    public static UserRole fromValue(int value) {
        for (UserRole role : values()) {
            if (role.value == value) {
                return role;
            }
        }
        throw new IllegalArgumentException("Недопустимое значение роли: " + value);
    }
}

class Shoes implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    String name;
    String article;
    String prise;
    String manufacturer;
    String size;
    String number_of_pairs;

    public Shoes() {}

    @Override
    public String toString() {
        return String.format("Название: %s Артикул: %s Цена: %s Производитель: %s Размер: %s Количество пар: %s",
                name, article, prise, manufacturer, size, number_of_pairs);
    }
}

class User implements Serializable {
    String login;
    String password;
    UserRole role;

    public User(String login, String password, UserRole role) {
        this.login = login;
        this.password = password;
        this.role = role;
    }

    @Override
    public String toString() {
        return String.format("%s (%s)", login, role == UserRole.ROLE_ADMIN ? "Admin" : "User");
    }
}

class AppState implements Serializable {
    List<User> users = new ArrayList<>();
    List<Shoes> shoes = new ArrayList<>();
    int currentUserId = -1;
    UserRole currentUserRole = UserRole.ROLE_USER;
}

public class Main {
    private static final int MAX_USERS = 50;
    private static final int MAX_SHOES = 100;
    private static final int MAX_NAME_LENGTH = 50;
    private static final int MAX_ARTICLE_LENGTH = 10;
    private static final int MAX_PRISE_LENGTH = 20;
    private static final int MAX_LOGIN_LENGTH = 20;
    private static final int MAX_PASSWORD_LENGTH = 20;
    private static final int MAX_PAIRS_LENGTH = 10;
    private static final int MAX_SIZE_LENGTH = 3;
    private static final int MAX_MANUFACTURER_LENGTH = 100;
    private static final String USERS_FILE = "users.dat";
    private static final String SHOES_FILE = "shoes.dat";

    // Список известных производителей обуви для проверки
    private static final String[] KNOWN_MANUFACTURERS = {
            "Nike", "Adidas", "Reebok", "Puma", "Geox", "Ecco",
            "Salomon", "Timberland", "Clarks", "Converse", "Vans",
            "New Balance", "Skechers", "Dr. Martens", "Steve Madden",
            "Bata", "CAT", "Merrell", "Ralf Ringer", "Columbia"
    };

    private final AppState state;
    private final Scanner scanner;

    public Main() {
        this.state = new AppState();
        this.scanner = new Scanner(System.in);
    }

    private int readInt() {
        while (true) {
            try {
                int value = scanner.nextInt();
                scanner.nextLine(); // очищаем буфер после nextInt()
                return value;
            } catch (InputMismatchException e) {
                System.out.println("Ошибка: введите число!");
                scanner.nextLine(); // очищаем некорректный ввод
            }
        }
    }

    private void pressAnyKeyToContinue() {
        System.out.println("\nНажмите Enter чтобы продолжить...");
        scanner.nextLine();
    }

    private void clearConsole() {
        try {
            final String os = System.getProperty("os.name");
            if (os.contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            }
        } catch (final Exception e) {
            for (int i = 0; i < 50; i++) {
                System.out.println();
            }
        }
    }
    @SuppressWarnings("unchecked")
    private boolean loadUsers() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(USERS_FILE))) {
            state.users = (List<User>) ois.readObject();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            return false;
        }
    }

    private boolean saveUsers() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USERS_FILE))) {
            oos.writeObject(state.users);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void createDefaultAdmin() {
        state.users.clear();
        state.users.add(new User("admin", "admin", UserRole.ROLE_ADMIN));
        if (!saveUsers()) {
            System.out.println("Ошибка при создании файла пользователей");
            return;
        }
        System.out.println("Стандартный администратор создан. Login: admin Password: admin");
        pressAnyKeyToContinue();
    }

    private boolean isLoginValid(String login) {
        return login != null && !login.isEmpty() && login.length() <= MAX_LOGIN_LENGTH;
    }

    private boolean isPasswordValid(String password) {
        return password != null && !password.isEmpty() && password.length() <= MAX_PASSWORD_LENGTH;
    }

    private boolean isLoginUnique(String login) {
        return state.users.stream().noneMatch(user -> user.login.equals(login));
    }

    private boolean verifyCredentials(String login, String password) {
        for (int i = 0; i < state.users.size(); i++) {
            User user = state.users.get(i);
            if (user.login.equals(login) && user.password.equals(password)) {
                state.currentUserId = i;
                state.currentUserRole = user.role;
                return true;
            }
        }
        return false;
    }

    private void addUser() {
        if (state.users.size() >= MAX_USERS) {
            System.out.println("Достигнуто максимальное количество пользователей (" + MAX_USERS + ")");
            pressAnyKeyToContinue();
            return;
        }

        System.out.print("Введите логин: ");
        String login = scanner.nextLine();

        if (login.length() > MAX_LOGIN_LENGTH) {
            System.out.println("Ошибка: введено " + login.length() + " символов (максимум " + MAX_LOGIN_LENGTH + ").");
            pressAnyKeyToContinue();
            return;
        }

        if (!isLoginUnique(login)) {
            System.out.println("Логин уже существует");
            pressAnyKeyToContinue();
            return;
        }

        System.out.print("Введите пароль: ");
        String password = scanner.nextLine();

        if (password.length() > MAX_PASSWORD_LENGTH) {
            System.out.println("Ошибка: введено " + password.length() + " символов (максимум " + MAX_PASSWORD_LENGTH + ").");
            pressAnyKeyToContinue();
            return;
        }

        System.out.print("Введите роль (1 - admin, 2 - user): ");
        int roleValue = readInt();

        if (roleValue != 1 && roleValue != 2) {
            System.out.println("Неправильная роль");
            pressAnyKeyToContinue();
            return;
        }

        UserRole role = UserRole.fromValue(roleValue);
        state.users.add(new User(login, password, role));

        if (saveUsers()) {
            System.out.println("Пользователь успешно добавлен");
        } else {
            System.out.println("Не удалось сохранить данные пользователя");
        }
        pressAnyKeyToContinue();
    }

    private void editUser() {
        if (state.users.isEmpty()) {
            System.out.println("Пользователь не найден");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("Список пользователей:");
        for (int i = 0; i < state.users.size(); i++) {
            System.out.println((i + 1) + ". " + state.users.get(i));
        }
        System.out.print("\nВыберите пользователя для редактирования (0 чтобы выйти): ");
        int choice = readInt();

        if (choice == 0) {
            return;
        }

        if (choice < 1 || choice > state.users.size()) {
            System.out.println("Неправильный выбор");
            pressAnyKeyToContinue();
            return;
        }

        int userIndex = choice - 1;
        if (userIndex == state.currentUserId) {
            System.out.println("Вы не можете редактировать здесь свой собственный аккаунт");
            pressAnyKeyToContinue();
            return;
        }

        User user = state.users.get(userIndex);
        System.out.println("\nИзменение данных пользователя " + user.login);
        System.out.println("1. Изменить пароль");
        System.out.println("2. Изменить роль");
        System.out.println("0. Закрыть");
        System.out.print("Выбор: ");

        choice = readInt();

        switch (choice) {
            case 1:
                System.out.print("Новый пароль: ");
                user.password = scanner.nextLine();
                System.out.println("Пароль успешно изменён");
                break;
            case 2:
                System.out.print("Новая роль (1 - admin, 2 - user): ");
                int roleValue = readInt();
                if (roleValue == 1 || roleValue == 2) {
                    user.role = UserRole.fromValue(roleValue);
                    System.out.println("Роль успешно изменена");
                } else {
                    System.out.println("Неправильная роль");
                }
                break;
            case 0:
                return;
            default:
                System.out.println("Неправильный выбор");
                break;
        }

        if (choice == 1 || choice == 2) {
            saveUsers();
        }
    }

    private void deleteUser() {
        if (state.users.isEmpty()) {
            System.out.println("Пользователь не найден");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("Список пользователей:");
        for (int i = 0; i < state.users.size(); i++) {
            System.out.println((i + 1) + ". " + state.users.get(i));
        }

        System.out.print("\nВыбрать пользователя для удаления (0 для отмены): ");
        int choice = readInt();

        if (choice < 1 || choice > state.users.size()) {
            if (choice != 0) {
                System.out.println("Неверный выбор");
            }
            pressAnyKeyToContinue();
            return;
        }

        int userIndex = choice - 1;
        if (userIndex == state.currentUserId) {
            System.out.println("Вы не можете удалить свой же аккаунт");
            pressAnyKeyToContinue();
            return;
        }

        User user = state.users.get(userIndex);
        System.out.print("Вы уверены что хотите удалить пользователя " + user.login + "? (1 - Да, 0 - Нет): ");
        choice = readInt();

        if (choice == 1) {
            state.users.remove(userIndex);
            if (state.currentUserId > userIndex) {
                state.currentUserId--;
            }
            if (saveUsers()) {
                System.out.println("Пользователь успешно удалён");
            } else {
                System.out.println("Операция отменена");
            }
        }
        pressAnyKeyToContinue();
    }

    @SuppressWarnings("unchecked")
    private boolean loadShoes() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(SHOES_FILE))) {
            state.shoes = (List<Shoes>) ois.readObject();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            return false;
        }
    }

    private boolean saveShoes() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(SHOES_FILE))) {
            oos.writeObject(state.shoes);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    private void createEmptyShoesFile() {
        state.shoes.clear();
        if (!saveShoes()) {
            System.out.println("Ошибка создания файла обуви");
            return;
        }
        System.out.println("Создан пустой файл для хранения данных о обуви");
    }

    // Метод для проверки производителя
    private boolean isValidManufacturer(String manufacturer) {
        if (manufacturer == null || manufacturer.trim().isEmpty()) {
            System.out.println("Ошибка: производитель не может быть пустым");
            return false;
        }

        manufacturer = manufacturer.trim();

        // Проверка длины
        if (manufacturer.length() > MAX_MANUFACTURER_LENGTH) {
            System.out.println("Ошибка: название производителя слишком длинное (максимум " + MAX_MANUFACTURER_LENGTH + " символов)");
            return false;
        }

        if (manufacturer.length() < 2) {
            System.out.println("Ошибка: название производителя слишком короткое (минимум 2 символа)");
            return false;
        }

        // Проверка на некорректные паттерны
        if (manufacturer.matches(".*[0-9]{3,}.*")) {
            System.out.println("Ошибка: название производителя не должно содержать 3 и более цифр подряд");
            return false;
        }

        if (manufacturer.matches(".*[А-ЯA-Z]{4,}.*")) {
            System.out.println("Ошибка: название производителя не должно содержать 4 и более заглавных букв подряд");
            return false;
        }

        // Проверка на повторяющиеся символы (например: РРР)
        if (manufacturer.matches(".*(.)\\1\\1.*")) {
            System.out.println("Ошибка: название производителя содержит повторяющиеся символы (например: РРР, ААА)");
            return false;
        }

        // Проверка на известные бренды (опционально, с подсказкой)
        String lowerManufacturer = manufacturer.toLowerCase();
        boolean isKnownBrand = false;
        for (String brand : KNOWN_MANUFACTURERS) {
            if (lowerManufacturer.contains(brand.toLowerCase())) {
                isKnownBrand = true;
                break;
            }
        }

        if (!isKnownBrand) {
            System.out.println("Предупреждение: '" + manufacturer + "' не найден в списке известных производителей обуви.");
            System.out.println("Известные производители: " + String.join(", ", Arrays.copyOfRange(KNOWN_MANUFACTURERS, 0, Math.min(5, KNOWN_MANUFACTURERS.length))) + "...");
            System.out.print("Продолжить с этим производителем? (1 - Да, 0 - Нет): ");
            String confirm = scanner.nextLine();
            return confirm.equals("1");
        }

        return true;
    }

    // Метод для проверки размера обуви
    private boolean isValidSize(String size) {
        if (size == null || size.trim().isEmpty()) {
            System.out.println("Ошибка: размер не может быть пустым");
            return false;
        }

        // Проверка, что размер состоит только из цифр
        if (!size.matches("\\d+")) {
            System.out.println("Ошибка: размер должен содержать только цифры");
            return false;
        }

        if (size.length() > MAX_SIZE_LENGTH) {
            System.out.println("Ошибка: размер слишком длинный (максимум " + MAX_SIZE_LENGTH + " символов)");
            return false;
        }

        try {
            int sizeNum = Integer.parseInt(size);
            // Проверка диапазона размера (0-50)
            if (sizeNum < 0 || sizeNum > 50) {
                System.out.println("Ошибка: размер должен быть в диапазоне от 0 до 50");
                return false;
            }
        } catch (NumberFormatException e) {
            System.out.println("Ошибка: некорректный формат размера");
            return false;
        }

        return true;
    }

    private Shoes inputShoesDetails() {
        Shoes shoes = new Shoes();
        System.out.print("Название товара: ");
        do {
            shoes.name = scanner.nextLine();
            if (shoes.name.length() > MAX_NAME_LENGTH) {
                System.out.println("Ошибка: максимум " + MAX_NAME_LENGTH + " символов. Повторите ввод:");
            }
        } while (shoes.name.length() > MAX_NAME_LENGTH);

        System.out.print("Артикул: ");
        do {
            shoes.article = scanner.nextLine();
            boolean valid = shoes.article.matches("^[МЖД]-\\d{7}$");
            if (!valid) {
                System.out.println("Ошибка: артикул должен быть в формате М/Ж/Д-1234567. Повторите ввод:");
            } else if (shoes.article.length() > MAX_ARTICLE_LENGTH) {
                System.out.println("Ошибка: максимум " + MAX_ARTICLE_LENGTH + " символов. Повторите ввод:");
                valid = false;
            }
            if (valid) break;
        } while (true);

        System.out.print("Цена: ");
        do {
            shoes.prise = scanner.nextLine();
            boolean isNumeric = !shoes.prise.isEmpty();
            for (int i = 0; i < shoes.prise.length() && isNumeric; i++) {
                if (!Character.isDigit(shoes.prise.charAt(i))) {
                    isNumeric = false;
                }
            }
            if (!isNumeric) {
                System.out.println("Ошибка: цена должна содержать только цифры. Повторите ввод:");
            } else if (shoes.prise.length() > MAX_PRISE_LENGTH) {
                System.out.println("Ошибка: максимум " + MAX_PRISE_LENGTH + " символов. Повторите ввод:");
                isNumeric = false;
            }
            if (isNumeric) break;
        } while (true);

        System.out.print("Производитель: ");
        do {
            shoes.manufacturer = scanner.nextLine().trim();
            if (!isValidManufacturer(shoes.manufacturer)) {
                System.out.print("Введите производителя заново: ");
            } else {
                break;
            }
        } while (true);

        System.out.print("Размер (0-50): ");
        do {
            shoes.size = scanner.nextLine().trim();
            if (!isValidSize(shoes.size)) {
                System.out.print("Введите размер заново (0-50): ");
            } else {
                break;
            }
        } while (true);

        System.out.print("Количество пар: ");
        do {
            shoes.number_of_pairs = scanner.nextLine();
            boolean isNumeric = !shoes.number_of_pairs.isEmpty();
            for (int i = 0; i < shoes.number_of_pairs.length() && isNumeric; i++) {
                if (!Character.isDigit(shoes.number_of_pairs.charAt(i))) {
                    isNumeric = false;
                }
            }
            if (!isNumeric) {
                System.out.println("Ошибка: количество пар должно содержать только цифры. Повторите ввод:");
            } else if (shoes.number_of_pairs.length() > MAX_PAIRS_LENGTH) {
                System.out.println("Ошибка: максимум " + MAX_PAIRS_LENGTH + " символов. Повторите ввод:");
                isNumeric = false;
            }
            if (isNumeric) break;
        } while (true);

        return shoes;
    }

    private void addShoes() {
        if (state.shoes.size() >= MAX_SHOES) {
            System.out.println("Достигнуто максимальное количество пар обуви (" + MAX_SHOES + ")");
            pressAnyKeyToContinue();
            return;
        }

        Shoes newShoes = inputShoesDetails();
        state.shoes.add(newShoes);

        if (saveShoes()) {
            System.out.println("\nТовар добавлен успешно");
        } else {
            System.out.println("\nОшибка сохранения данных о товаре");
        }
        pressAnyKeyToContinue();
    }

    private void displayShoesList(List<Shoes> shoesList) {
        for (int i = 0; i < shoesList.size(); i++) {
            System.out.println((i + 1) + ". " + shoesList.get(i));
        }
    }
    private void editShoes() {
        if (state.shoes.isEmpty()) {
            System.out.println("Товары не найдены");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("Список обуви:");
        displayShoesList(state.shoes);

        System.out.print("\nВыберите модель обуви для редактирования (0 для отмены): ");
        int choice = readInt();

        if (choice < 1 || choice > state.shoes.size()) {
            if (choice != 0) {
                System.out.println("Неверный выбор");
                pressAnyKeyToContinue();
            }
            return;
        }

        Shoes shoes = state.shoes.get(choice - 1);
        int editChoice;

        do {
            clearConsole();
            System.out.println("\nРедактирование товара: " + shoes.name);
            System.out.println("1. Изменить название");
            System.out.println("2. Изменить артикул");
            System.out.println("3. Изменить цену");
            System.out.println("4. Изменить производителя");
            System.out.println("5. Изменить размер");
            System.out.println("6. Изменить количество пар");
            System.out.println("0. Завершить редактирование");
            System.out.print("Выбор: ");
            editChoice = readInt();

            switch (editChoice) {
                case 1:
                    System.out.print("Новое название: ");
                    shoes.name = scanner.nextLine();
                    break;

                case 2:
                    String newArticle;
                    do {
                        System.out.print("Новый артикул (формат: М/Ж/Д-1234567): ");
                        newArticle = scanner.nextLine();
                        boolean valid = newArticle.matches("^[МЖД]-\\d{7}$");
                        if (!valid) {
                            System.out.println("Ошибка: артикул должен быть в формате М/Ж/Д-1234567. Повторите ввод.");
                        } else if (newArticle.length() > MAX_ARTICLE_LENGTH) {
                            System.out.println("Ошибка: максимум " + MAX_ARTICLE_LENGTH + " символов. Повторите ввод.");
                            valid = false;
                        }
                        if (valid) {
                            shoes.article = newArticle;
                            break;
                        }
                    } while (true);
                    break;

                case 3:
                    System.out.print("Новая цена: ");
                    shoes.prise = scanner.nextLine();
                    break;

                case 4:
                    String newManufacturer;
                    do {
                        System.out.print("Новый производитель: ");
                        newManufacturer = scanner.nextLine().trim();
                        if (!isValidManufacturer(newManufacturer)) {
                            System.out.print("Введите производителя заново: ");
                        } else {
                            shoes.manufacturer = newManufacturer;
                            break;
                        }
                    } while (true);
                    break;

                case 5:
                    String newSize;
                    do {
                        System.out.print("Новый размер (0-50): ");
                        newSize = scanner.nextLine().trim();
                        if (!isValidSize(newSize)) {
                            System.out.print("Введите размер заново (0-50): ");
                        } else {
                            shoes.size = newSize;
                            break;
                        }
                    } while (true);
                    break;

                case 6:
                    System.out.print("Новое количество пар: ");
                    shoes.number_of_pairs = scanner.nextLine();
                    break;
            }

            if (editChoice != 0) {
                pressAnyKeyToContinue();
            }
        } while (editChoice != 0);
        if (saveShoes()) {
            System.out.println("Изменения сохранены успешно");
        } else {
            System.out.println("Ошибка сохранения изменений");
        }
        pressAnyKeyToContinue();
    }

    private void deleteShoes() {
        if (state.shoes.isEmpty()) {
            System.out.println("Обувь не найдена");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("Список обуви:");
        displayShoesList(state.shoes);

        System.out.print("\nВыберите обувь для удаления (0 для отмены): ");
        int choice = readInt();

        if (choice == 0) {
            pressAnyKeyToContinue();
            return;
        }

        if (choice < 1 || choice > state.shoes.size()) {
            System.out.println("Неверный выбор");
            pressAnyKeyToContinue();
            return;
        }

        Shoes shoesToDelete = state.shoes.get(choice - 1);

        System.out.print("Вы уверены, что хотите удалить " + shoesToDelete.name + "? (1 - Да, 0 - Нет): ");
        int confirm = readInt();

        if (confirm == 1) {
            state.shoes.remove(shoesToDelete);
            if (saveShoes()) {
                System.out.println("Информация о обуви удалена");
            } else {
                System.out.println("Ошибка сохранения изменений");
            }
        }
        pressAnyKeyToContinue();
    }

    private void searchShoes() {
        if (state.shoes.isEmpty()) {
            System.out.println("Нет обуви для поиска");
            pressAnyKeyToContinue();
            return;
        }

        while (true) {
            clearConsole();
            System.out.println("\n=== ПОИСК ТОВАРОВ ===");
            System.out.println("1. Поиск по названию");
            System.out.println("2. Поиск по цене");
            System.out.println("3. Поиск по производителю");
            System.out.println("0. Выход из меню поиска");
            System.out.print("Выбор: ");

            String choiceStr = scanner.nextLine().trim();
            int choice;

            try {
                choice = Integer.parseInt(choiceStr);
            } catch (NumberFormatException e) {
                System.out.println("Ошибка: нужно ввести число от 0 до 3");
                continue;
            }

            if (choice == 0) {
                System.out.println("Выход из меню поиска...");
                break;
            }

            List<Shoes> results = new ArrayList<>();

            switch (choice) {
                case 1:
                    System.out.print("Введите название для поиска: ");
                    String nameQuery = scanner.nextLine().trim().toLowerCase();
                    if (nameQuery.isEmpty()) {
                        System.out.println("Пустой запрос");
                        break;
                    }
                    for (Shoes s : state.shoes) {
                        if (s.name.toLowerCase().contains(nameQuery)) {
                            results.add(s);
                        }
                    }
                    break;

                case 2:
                    System.out.print("Введите цену для поиска: ");
                    String priceQuery = scanner.nextLine().trim();
                    if (priceQuery.isEmpty()) {
                        System.out.println("Пустой запрос");
                        break;
                    }
                    for (Shoes s : state.shoes) {
                        if (s.prise.equals(priceQuery)) {
                            results.add(s);
                        }
                    }
                    break;
                case 3:
                    System.out.print("Введите производителя для поиска: ");
                    String manufacturerQuery = scanner.nextLine().trim().toLowerCase();
                    if (manufacturerQuery.isEmpty()) {
                        System.out.println("Пустой запрос");
                        break;
                    }
                    for (Shoes s : state.shoes) {
                        if (s.manufacturer.toLowerCase().contains(manufacturerQuery)) {
                            results.add(s);
                        }
                    }
                    break;

                default:
                    System.out.println("Неверный выбор. Введите число от 0 до 3");
                    continue;
            }

            if (results.isEmpty()) {
                System.out.println("Обувь не найдена");
            } else {
                System.out.println("\n=== РЕЗУЛЬТАТЫ ПОИСКА ===");
                System.out.println("Найдено обуви: " + results.size());
                displayShoesList(results);
            }
            pressAnyKeyToContinue();
        }
    }

    private void listArticlesWithPairs() {
        if (state.shoes.isEmpty()) {
            System.out.println("Обувь не найдена");
            pressAnyKeyToContinue();
            return;
        }

        System.out.print("Введите артикул: ");
        String articleQuery = scanner.nextLine().trim();

        System.out.print("Введите размер: ");
        String sizeQuery = scanner.nextLine().trim();

        List<Shoes> results = new ArrayList<>();

        for (Shoes shoes : state.shoes) {
            if (shoes.article.equalsIgnoreCase(articleQuery) &&
                    shoes.size.equalsIgnoreCase(sizeQuery)) {
                results.add(shoes);
            }
        }

        System.out.println("\n=== РЕЗУЛЬТАТ ПОИСКА ===\n");
        if (results.isEmpty()) {
            System.out.println("Обувь с артикулом " + articleQuery +
                    " и размером " + sizeQuery + " не найдена");
        } else {
            for (Shoes s : results) {
                System.out.println("Название: " + s.name +
                        ", Артикул: " + s.article +
                        ", Размер: " + s.size +
                        ", Количество пар: " + s.number_of_pairs +
                        ", Цена: " + s.prise +
                        ", Производитель: " + s.manufacturer);
            }
        }
        pressAnyKeyToContinue();
    }

    private void sortShoes() {
        if (state.shoes.isEmpty()) {
            System.out.println("Нет обуви для сортировки");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("Сортировка по:");
        System.out.println("1. Названию");
        System.out.println("2. Цене");
        System.out.println("3. Производителю");
        System.out.println("4. Количеству пар");
        System.out.print("Выбор: ");

        int choice = readInt();

        switch (choice) {
            case 1:
                state.shoes.sort(Comparator.comparing(d -> d.name));
                System.out.println("Обувь отсортирована по названию");
                break;
            case 2:
                state.shoes.sort(Comparator.comparingInt(d -> Integer.parseInt(d.prise)));
                System.out.println("Обувь отсортирована по цене");
                break;
            case 3:
                state.shoes.sort(Comparator.comparing(d -> d.manufacturer));
                System.out.println("Обувь отсортирована по производителю");
                break;
            case 4:
                state.shoes.sort(Comparator.comparingInt(d -> Integer.parseInt(d.number_of_pairs)));
                System.out.println("Обувь отсортирована по количеству пар");
                break;
            default:
                System.out.println("Неверный выбор");
                break;
        }
        pressAnyKeyToContinue();
    }
    private void displayShoes() {
        if (state.shoes.isEmpty()) {
            System.out.println("Обувь не найдена");
            pressAnyKeyToContinue();
            return;
        }

        System.out.println("=== СПИСОК ТОВАРОВ ===\n");
        displayShoesList(state.shoes);
        pressAnyKeyToContinue();
    }

    private void showUserMenu() {
        int choice;
        do {
            clearConsole();
            System.out.println("\n=== МЕНЮ ПОЛЬЗОВАТЕЛЯ ===");
            System.out.println("1. Просмотреть все модели обуви");
            System.out.println("2. Поиск обуви");
            System.out.println("3. Поиск обуви по заданному артикулу и размеру");
            System.out.println("4. Сортировка обуви");
            System.out.println("0. Выход");
            System.out.print("\nВыбор: ");
            choice = readInt();

            switch (choice) {
                case 1:
                    displayShoes();
                    break;
                case 2:
                    searchShoes();
                    break;
                case 3:
                    listArticlesWithPairs();
                    break;
                case 4:
                    sortShoes();
                    break;
                case 0:
                    state.currentUserId = -1;
                    scanner.nextLine();
                    break;
                default:
                    System.out.println("Неверный выбор");
                    pressAnyKeyToContinue();
                    break;
            }
        } while (choice != 0);
    }

    private void showUserManagementMenu() {
        int choice;
        do {
            clearConsole();
            System.out.println("\n=== УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ===");
            System.out.println("1. Просмотреть всех пользователей");
            System.out.println("2. Добавить пользователя");
            System.out.println("3. Редактировать пользователя");
            System.out.println("4. Удалить пользователя");
            System.out.println("0. Назад");
            System.out.print("\nВыбор: ");
            choice = readInt();

            switch (choice) {
                case 1:
                    System.out.println("\n=== СПИСОК ПОЛЬЗОВАТЕЛЕЙ ===\n");
                    for (int i = 0; i < state.users.size(); i++) {
                        System.out.println((i + 1) + ". " + state.users.get(i));
                    }
                    pressAnyKeyToContinue();
                    break;
                case 2:
                    addUser();
                    break;
                case 3:
                    editUser();
                    break;
                case 4:
                    deleteUser();
                    break;
                case 0:
                    break;
                default:
                    System.out.println("Неверный выбор");
                    pressAnyKeyToContinue();
                    break;
            }
        } while (choice != 0);
    }

    private void showShoesManagementMenu() {
        int choice;
        do {
            clearConsole();
            System.out.println("\n=== УПРАВЛЕНИЕ ТОВАРАМИ ===");
            System.out.println("1. Просмотреть все модели обуви");
            System.out.println("2. Добавить модель обуви");
            System.out.println("3. Редактировать модель обуви");
            System.out.println("4. Удалить модель обуви");
            System.out.println("5. Поиск обуви по параметрам");
            System.out.println("6. Поиск обуви по артикулу и размеру");
            System.out.println("7. Сортировка обуви по параметрам ");
            System.out.println("0. Назад");
            System.out.print("\nВыбор: ");
            choice = readInt();
            switch (choice) {
                case 1:
                    displayShoes();
                    break;
                case 2:
                    addShoes();
                    break;
                case 3:
                    editShoes();
                    break;
                case 4:
                    deleteShoes();
                    break;
                case 5:
                    searchShoes();
                    break;
                case 6:
                    listArticlesWithPairs();
                    break;
                case 7:
                    sortShoes();
                    break;
                case 0:
                    break;
                default:
                    System.out.println("Неверный выбор");
                    pressAnyKeyToContinue();
                    break;
            }
        } while (choice != 0);
    }

    private void showAdminMenu() {
        int choice;
        do {
            clearConsole();
            System.out.println("\n=== АДМИНИСТРАТОРСКОЕ МЕНЮ ===");
            System.out.println("1. Управление пользователями");
            System.out.println("2. Управление моделями обуви");
            System.out.println("0. Выход");
            System.out.print("\nВыбор: ");
            choice = readInt();

            switch (choice) {
                case 1:
                    showUserManagementMenu();
                    break;
                case 2:
                    showShoesManagementMenu();
                    break;
                case 0:
                    state.currentUserId = -1;
                    break;
                default:
                    System.out.println("Неверный выбор");
                    pressAnyKeyToContinue();
                    break;
            }
        } while (choice != 0);
    }

    private void showLoginScreen() {
        while (state.currentUserId == -1) {
            System.out.println("\n=== БАЗА ДАННЫХ МАГАЗИНА ===");
            System.out.println("Пожалуйста, войдите в систему\n");

            System.out.print("Логин: ");
            String login = scanner.nextLine();

            System.out.print("Пароль: ");
            String password = scanner.nextLine();

            if (!isLoginValid(login)) {
                System.out.println("Неверный формат логина (максимум " + MAX_LOGIN_LENGTH + " символов)");
                pressAnyKeyToContinue();
                continue;
            }

            if (!isPasswordValid(password)) {
                System.out.println("Неверный формат пароля (максимум " + MAX_PASSWORD_LENGTH + " символов)");
                pressAnyKeyToContinue();
                continue;
            }

            if (verifyCredentials(login, password)) {
                System.out.println("\nВход выполнен успешно! Добро пожаловать, " + login + ".");
                state.currentUserId = 0;
                pressAnyKeyToContinue();
                break;
            } else {
                System.out.println("\nНеверный логин или пароль");
                pressAnyKeyToContinue();
            }
        }
    }

    private boolean initializeApp() {
        state.currentUserId = -1;
        state.currentUserRole = UserRole.ROLE_USER;

        boolean usersLoaded = loadUsers();
        boolean shoesLoaded = loadShoes();

        if (!usersLoaded) {
            createDefaultAdmin();
            usersLoaded = loadUsers();
        }

        if (!shoesLoaded) {
            createEmptyShoesFile();
            shoesLoaded = loadShoes();
        }

        return usersLoaded && shoesLoaded;
    }

    public void run() {
        if (!initializeApp()) {
            System.out.println("Ошибка инициализации приложения");
            return;
        }

        while (true) {
            showLoginScreen();

            if (state.currentUserId == -1) {
                break;
            }

            if (state.currentUserRole == UserRole.ROLE_ADMIN) {
                showAdminMenu();
            } else {
                showUserMenu();
            }
        }
        System.out.println("\nДо свидания!");
        scanner.close();
    }

    public static void main(String[] args) {
        new Main().run();
    }
}

